// SPDX-License-Identifier: GPL-2.0-only
/* Real bounded panic producer: no allocation/lookup/blocking lock boundary. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint32_t u32;
typedef uint64_t u64;
typedef uint8_t u8;
typedef u64 mk_phys_cpu_t;
typedef struct { unsigned int value; } atomic_t;
#define MK_MSG_SYSTEM 0x3000
#define MK_SYS_HALTED 0x3004
#define MK_SYS_SHUTDOWN 0x3002
#define MK_PHYS_CPU_INVALID UINT64_MAX
#define MK_IPI_RING_SIZE 64
#define SBI_EXT_IPI 0x735049
#define SBI_EXT_IPI_SEND_IPI 0
#define READ_ONCE(x) (x)
#define smp_load_acquire(p) (*(p))
#define smp_store_release(p, v) (*(p) = (v))
#define __aligned(x) __attribute__((aligned(x)))
struct mk_message { u32 msg_type, msg_subtype; u64 msg_id; u32 payload_len; u8 payload[]; };
struct mk_resource_ack { u32 operation, result; u64 resource_id; };
struct mk_ipi_data { u64 sender_cpu; unsigned int type; size_t data_size; char buffer[4096]; };
struct mk_shared_data {
	struct { atomic_t head, tail; struct mk_ipi_data entries[64]; } ring;
};
struct mk_instance { struct mk_shared_data *ipi_data; u64 ipi_target; int id; bool ipi_lock; };
static struct mk_shared_data ring;
static struct mk_instance parent, self = { .id = 1 }, *mk_self = &self;
static struct mk_instance *mk_parent_endpoint;
static atomic_t mk_halt_notice;
static unsigned int sends, cas_calls;
static bool irq_disabled;
static unsigned int atomic_read(atomic_t *p) { return p->value; }
static unsigned int atomic_read_acquire(atomic_t *p) { return p->value; }
static unsigned int atomic_cmpxchg(atomic_t *p, unsigned int old, unsigned int new)
{
	unsigned int actual = p->value;
	cas_calls++;
	if (actual == old)
		p->value = new;
	return actual;
}
#define local_irq_save(flags) do { (flags) = irq_disabled; irq_disabled = true; } while (0)
#define local_irq_restore(flags) do { irq_disabled = (flags); } while (0)
static bool raw_spin_trylock(bool *lock)
{
	if (*lock)
		return false;
	*lock = true;
	return true;
}
static void raw_spin_unlock(bool *lock) { assert(*lock); *lock = false; }
static unsigned int smp_processor_id(void) { return 0; }
static u64 arch_cpu_physical_id(unsigned int cpu) { return 65537; }
struct sbiret { long error, value; };
static struct sbiret sbi_ecall(unsigned long ext, unsigned long fid,
			     unsigned long mask, unsigned long base,
			     unsigned long a2, unsigned long a3,
			     unsigned long a4, unsigned long a5)
{
	assert(ext == SBI_EXT_IPI && fid == SBI_EXT_IPI_SEND_IPI);
	assert(mask == 1 && base == 7 && !a2 && !a3 && !a4 && !a5);
	assert(!parent.ipi_lock && !irq_disabled);
	sends++;
	return (struct sbiret) { .error = -EPERM };
}
#include "notice.h"

static void reset(void)
{
	memset(&ring, 0, sizeof(ring));
	parent = (struct mk_instance) { .ipi_data = &ring, .ipi_target = 7 };
	mk_parent_endpoint = &parent;
	mk_halt_notice.value = 0;
	sends = cas_calls = 0;
	irq_disabled = false;
}

int main(void)
{
	struct mk_resource_ack ack;
	struct mk_message *msg;

	reset();
	mk_riscv_notify_parent_halted();
	assert(sends == 1 && ring.ring.head.value == 1);
	msg = (void *)ring.ring.entries[0].buffer;
	assert(msg->msg_type == MK_MSG_SYSTEM && msg->msg_subtype == MK_SYS_HALTED);
	assert(!msg->msg_id && msg->payload_len == sizeof(ack));
	memcpy(&ack, msg->payload, sizeof(ack));
	assert(ack.operation == MK_SYS_SHUTDOWN && !ack.result && ack.resource_id == 1);
	assert(ring.ring.entries[0].sender_cpu == 65537);
	assert(ring.ring.entries[0].data_size == sizeof(*msg) + sizeof(ack));
	mk_riscv_notify_parent_halted();
	assert(sends == 1);
	reset();
	parent.ipi_lock = true;
	mk_riscv_notify_parent_halted();
	assert(!sends && !ring.ring.head.value && parent.ipi_lock && !irq_disabled);
	reset();
	ring.ring.head.value = 63;
	mk_riscv_notify_parent_halted();
	assert(!sends && ring.ring.head.value == 63 && !parent.ipi_lock);
	reset();
	parent.ipi_data = NULL;
	mk_riscv_notify_parent_halted();
	assert(!sends && !parent.ipi_lock);
	reset();
	mk_parent_endpoint = NULL;
	mk_riscv_notify_parent_halted();
	assert(!sends);
	puts("PASS: one-shot nonblocking halt notice; full/retired/contended endpoints skipped");
	return 0;
}
