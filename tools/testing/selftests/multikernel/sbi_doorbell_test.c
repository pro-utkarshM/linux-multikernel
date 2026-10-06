// SPDX-License-Identifier: GPL-2.0-only
/* Real SBI interrupt/send paths, controlled firmware and ring boundaries. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef uint64_t mk_phys_cpu_t;
#define SBI_EXT_IPI 0x735049
#define SBI_EXT_IPI_SEND_IPI 0
#define MK_PHYS_CPU_INVALID UINT64_MAX
#define CSR_IP 0
#define IE_SIE 2
#define pr_warn_once(...) do { } while (0)
#define printk_deferred(...) do { } while (0)
#define KERN_WARNING ""
struct sbiret { long error, value; };
struct irq_chip { int unused; };
struct irq_desc { struct irq_chip chip; };
static bool entered, cleared, mk_receiver_ready;
struct mk_instance { void *ipi_data; };
static struct mk_instance self = { .ipi_data = &self };
static struct mk_instance *mk_self = &self, *host_instance, *mk_parent_endpoint;
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, value) ((x) = (value))
#define smp_processor_id() current_cpu
#define smp_store_release(p, value) (*(p) = (value))
#define EBUSY 16
#define __init
#define CPUHP_BP_PREPARE_DYN 100
#define CPUHP_TEARDOWN_CPU 200
#define CPUHP_AP_ONLINE_DYN 250
static int registered_state;
/* This fixture is the host receiver; spawn qualification has its own test. */
struct list_head { struct list_head *next, *prev; };
struct syscore_ops;
struct syscore { struct list_head node; const struct syscore_ops *ops; void *data; };
static struct syscore mk_riscv_syscore;
static bool mk_spawned(void) { return false; }
static void register_syscore(struct syscore *entry)
{
	assert(!"host must not register shutdown qualification");
}
static struct mk_instance *mk_instance_get(struct mk_instance *p) { return p; }
static int cpuhp_setup_state_nocalls(int state, const char *name,
				   int (*up)(unsigned int), int (*down)(unsigned int))
{
	registered_state = state;
	return state;
}
static unsigned int current_cpu, native_pending, ring_pending, native_seen, ring_seen;
static unsigned int sends;
static mk_phys_cpu_t target;
static struct irq_chip *irq_desc_get_chip(struct irq_desc *d) { return &d->chip; }
static void chained_irq_enter(struct irq_chip *c, struct irq_desc *d) { entered = true; }
static void chained_irq_exit(struct irq_chip *c, struct irq_desc *d) { entered = false; }
static void csr_clear(int csr, int bit) { assert(entered); cleared = true; }
static void ipi_mux_process(void)
{
	assert(entered && cleared);
	native_seen += native_pending;
	native_pending = 0;
}
static void generic_multikernel_interrupt(void)
{
	assert(entered && cleared && !native_pending);
	ring_seen += ring_pending;
	ring_pending = 0;
}
static struct sbiret sbi_ecall(unsigned long ext, unsigned long fid,
			     unsigned long mask, unsigned long base,
			     unsigned long a2, unsigned long a3,
			     unsigned long a4, unsigned long a5)
{
	assert(ext == SBI_EXT_IPI && fid == SBI_EXT_IPI_SEND_IPI && mask == 1);
	assert(!a2 && !a3 && !a4 && !a5);
	target = base;
	sends++;
	return (struct sbiret) { 0 };
}
#include "receiver.h"
#include "irq.h"
#include "send.h"

int main(void)
{
	struct irq_desc desc;

	mk_arch_send_ipi(65537);
	assert(sends == 1 && target == 65537);
	mk_arch_send_ipi(MK_PHYS_CPU_INVALID);
	assert(sends == 1);
	assert(!mk_riscv_inbox_cpu());
	assert(mk_riscv_doorbell_init() == 0);
	assert(registered_state > CPUHP_TEARDOWN_CPU);
	assert(mk_riscv_receiver_offline(0) == -EBUSY);
	assert(mk_riscv_receiver_offline(1) == 0);
	mk_self = NULL;
	assert(!mk_riscv_inbox_cpu());
	mk_self = &self;
	ring_pending = 1;
	native_pending = 1;
	sbi_ipi_handle(&desc);
	assert(native_seen == 1 && ring_seen == 1 && !entered);
	sbi_ipi_handle(&desc);
	assert(native_seen == 1 && ring_seen == 1);
	current_cpu = 1;
	ring_pending = 1;
	native_pending = 1;
	sbi_ipi_handle(&desc);
	assert(native_seen == 2 && ring_seen == 1 && ring_pending == 1);
	current_cpu = 0;
	mk_receiver_ready = false;
	sbi_ipi_handle(&desc);
	assert(ring_pending == 1);
	mk_receiver_ready = true;
	sbi_ipi_handle(&desc);
	assert(ring_seen == 2 && !ring_pending);
	puts("PASS: physical SBI target, coalesced delivery and single initialized receiver");
	return 0;
}
