// SPDX-License-Identifier: GPL-2.0-only
/* Test-only #28 adapter: SBI software interrupts, not AIA/IMSIC transport. */
#include <linux/cpu.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kexec.h>
#include <linux/multikernel.h>
#include <linux/panic.h>
#include <linux/smp.h>
#include <linux/syscore_ops.h>
#include <asm/sbi.h>
#ifdef MK_NATIVE_TEST_KERNEL
#include <linux/completion.h>
#include <linux/jiffies.h>
#include <linux/kthread.h>
#include "native_shutdown_fault.h"
#endif

static struct mk_instance *mk_parent_endpoint;
static atomic_t mk_halt_notice = ATOMIC_INIT(0);
static bool mk_receiver_ready;
static bool mk_halt_quiesced;

static void mk_riscv_shutdown_prepare(void *unused)
{
	/* Kexec uses syscore shutdown too, but later reopens CPU hotplug. */
	if (panic_in_progress() || kexec_in_progress)
		return;
	if (system_state != SYSTEM_HALT && system_state != SYSTEM_POWER_OFF &&
	    system_state != SYSTEM_RESTART)
		return;
	/*
	 * Normal shutdown has drained native CPU hotplug before syscore.
	 * Exclude local controllers and incoming resource mutations until stop.
	 * A contended controller leaves the parent retaining this instance.
	 */
#ifdef MK_NATIVE_TEST_KERNEL
	if (!mk_test_shutdown_begin())
		return;
#endif
	if (!mutex_trylock(&mk_overlay_mutex)) {
#ifdef MK_NATIVE_TEST_KERNEL
		mk_test_shutdown_end(true);
#endif
		return;
	}
#ifdef MK_NATIVE_TEST_KERNEL
	mk_test_shutdown_end(false);
#endif
	/* Pair with machine-stop's acquire before any ring publication. */
	smp_store_release(&mk_halt_quiesced, true);
}

static const struct syscore_ops mk_riscv_syscore_ops = {
	.shutdown = mk_riscv_shutdown_prepare,
};

static struct syscore mk_riscv_syscore = {
	.ops = &mk_riscv_syscore_ops,
};

void mk_riscv_notify_parent_halted(void)
{
	/* Pair with init's publication of the pinned parent endpoint. */
	struct mk_instance *parent = smp_load_acquire(&mk_parent_endpoint);
	struct mk_shared_data *data;
	struct mk_ipi_data *slot;
	struct mk_resource_ack ack = {
		.operation = MK_SYS_SHUTDOWN,
	};
	u8 buffer[sizeof(struct mk_message) + sizeof(ack)] __aligned(8) = { 0 };
	struct mk_message *msg = (void *)buffer;
	mk_phys_cpu_t target = MK_PHYS_CPU_INVALID;
	unsigned int head, next, tail, attempt;
	unsigned long flags;
	bool published = false;

	/* Direct machine-stop and panic do not establish no-new-starts proof. */
	if (!smp_load_acquire(&mk_halt_quiesced) || panic_in_progress())
		return;
	if (!parent || !mk_self || atomic_cmpxchg(&mk_halt_notice, 0, 1))
		return;
	local_irq_save(flags);
	/* Panic may interrupt a ring writer holding this very lock. */
	if (!raw_spin_trylock(&parent->ipi_lock)) {
		local_irq_restore(flags);
		return;
	}
	data = READ_ONCE(parent->ipi_data);
	target = parent->ipi_target;
	if (!data || target == MK_PHYS_CPU_INVALID)
		goto out;
	for (attempt = 0; attempt < 3; attempt++) {
		head = atomic_read(&data->ring.head) & (MK_IPI_RING_SIZE - 1);
		next = (head + 1) & (MK_IPI_RING_SIZE - 1);
		/* Pair with the consumer's release of cleared slot capacity. */
		tail = atomic_read_acquire(&data->ring.tail) & (MK_IPI_RING_SIZE - 1);
		if (next == tail)
			goto out;
		if (atomic_cmpxchg(&data->ring.head, head, next) == head)
			break;
	}
	if (attempt == 3)
		goto out;
	ack.resource_id = mk_self->id;
	msg->msg_type = MK_MSG_SYSTEM;
	msg->msg_subtype = MK_SYS_HALTED;
	msg->payload_len = sizeof(ack);
	memcpy(msg->payload, &ack, sizeof(ack));
	slot = &data->ring.entries[head];
	slot->sender_cpu = arch_cpu_physical_id(smp_processor_id());
	slot->type = MK_MSG_SYSTEM;
	memcpy(slot->buffer, buffer, sizeof(buffer));
	/* Publish the entire slot before the consumer observes its size. */
	smp_store_release(&slot->data_size, sizeof(buffer));
	published = true;
out:
	raw_spin_unlock(&parent->ipi_lock);
	local_irq_restore(flags);
	/* No console/logging path here, even when firmware denies the doorbell. */
	if (published)
		sbi_ecall(SBI_EXT_IPI, SBI_EXT_IPI_SEND_IPI, 1, target, 0, 0, 0, 0);
}

void mk_arch_send_ipi(mk_phys_cpu_t phys_cpu)
{
	struct sbiret ret;

	if (phys_cpu == MK_PHYS_CPU_INVALID)
		return;
	/* Mask base is a physical hart ID, not a Linux logical CPU index. */
	ret = sbi_ecall(SBI_EXT_IPI, SBI_EXT_IPI_SEND_IPI, 1, phys_cpu,
			0, 0, 0, 0);
	if (ret.error)
		printk_deferred(KERN_WARNING "multikernel: SBI IPI to hart %llu failed: %ld\n",
				phys_cpu, ret.error);
}

bool mk_riscv_inbox_cpu(void)
{
	/* Boot CPU is fixed for this bounded adapter: exactly one consumer. */
	return READ_ONCE(mk_receiver_ready) && smp_processor_id() == 0 &&
		mk_self && READ_ONCE(mk_self->ipi_data);
}

static int mk_riscv_receiver_offline(unsigned int cpu)
{
	return cpu == 0 && mk_self && READ_ONCE(mk_self->ipi_data) ? -EBUSY : 0;
}

static int __init mk_riscv_doorbell_init(void)
{
	int state;

	state = cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN,
					  "multikernel/sbi:receiver", NULL,
					  mk_riscv_receiver_offline);
	if (state < 0)
		return state;
	if (host_instance) {
		/* Publish the held reference before shutdown can use the endpoint. */
		smp_store_release(&mk_parent_endpoint, mk_instance_get(host_instance));
	}
	WRITE_ONCE(mk_receiver_ready, true);
	if (mk_spawned())
		register_syscore(&mk_riscv_syscore);
	return 0;
}
late_initcall(mk_riscv_doorbell_init);
