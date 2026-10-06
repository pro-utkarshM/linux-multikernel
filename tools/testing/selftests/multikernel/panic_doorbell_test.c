// SPDX-License-Identifier: GPL-2.0-only
/* Real shutdown qualification and bounded producer; kernel boundaries stubbed. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

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
#define WRITE_ONCE(x, v) ((x) = (v))
#define __init
#define CPUHP_AP_ONLINE_DYN 1
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
static bool mk_receiver_ready, mk_halt_quiesced, mk_overlay_mutex;
static bool spawn, panicking, kexec_in_progress;
static unsigned int overlay_attempts;
static int cpuhp_result;
static struct mk_instance *host_instance;
enum system_states { SYSTEM_BOOTING, SYSTEM_RUNNING, SYSTEM_HALT,
	SYSTEM_POWER_OFF, SYSTEM_RESTART };
static enum system_states system_state;
struct list_head { struct list_head *next, *prev; };
struct syscore_ops {
	int (*suspend)(void *data);
	void (*resume)(void *data);
	void (*shutdown)(void *data);
};
struct syscore { struct list_head node; const struct syscore_ops *ops; void *data; };
static struct syscore *registered;
static pthread_mutex_t mutex_guard = PTHREAD_MUTEX_INITIALIZER;
static bool mk_spawned(void) { return spawn; }
static bool panic_in_progress(void) { return panicking; }
static struct mk_instance *mk_instance_get(struct mk_instance *instance) { return instance; }
static void register_syscore(struct syscore *entry)
{
	assert(!registered);
	registered = entry;
}
static int cpuhp_setup_state_nocalls(int state, const char *name,
				   int (*online)(unsigned int),
				   int (*offline)(unsigned int))
{
	assert(state == CPUHP_AP_ONLINE_DYN && name && !online && offline);
	return cpuhp_result;
}
static bool mutex_trylock(bool *lock)
{
	assert(lock == &mk_overlay_mutex && !irq_disabled);
	pthread_mutex_lock(&mutex_guard);
	overlay_attempts++;
	if (*lock) {
		pthread_mutex_unlock(&mutex_guard);
		return false;
	}
	*lock = true;
	pthread_mutex_unlock(&mutex_guard);
	return true;
}
static void mutex_unlock(bool *lock)
{
	pthread_mutex_lock(&mutex_guard);
	assert(*lock);
	*lock = false;
	pthread_mutex_unlock(&mutex_guard);
}
#ifdef MK_NATIVE_TEST_KERNEL
struct completion { pthread_mutex_t lock; pthread_cond_t wake; bool done; };
#define DECLARE_COMPLETION(name) struct completion name = { PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, false }
#define HZ 1
#define __setup(name, fn)
#define IS_ERR(value) ((value) == NULL)
static unsigned int contention_proofs, contention_failures;
#define pr_info(...) (contention_proofs++)
#define pr_err(...) (contention_failures++)
static int kstrtobool(const char *value, bool *out)
{
	if (strcmp(value, "0") && strcmp(value, "1"))
		return -EINVAL;
	*out = !strcmp(value, "1");
	return 0;
}
static void complete(struct completion *c)
{
	pthread_mutex_lock(&c->lock);
	c->done = true;
	pthread_cond_broadcast(&c->wake);
	pthread_mutex_unlock(&c->lock);
}
static unsigned long wait_for_completion_timeout(struct completion *c, unsigned long timeout)
{
	struct timespec deadline;
	bool done;
	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += timeout;
	pthread_mutex_lock(&c->lock);
	while (!c->done)
		if (pthread_cond_timedwait(&c->wake, &c->lock, &deadline) == ETIMEDOUT)
			break;
	done = c->done;
	pthread_mutex_unlock(&c->lock);
	return done;
}
static bool fail_thread;
static int (*thread_fn)(void *);
static pthread_t holder;
static void *run_holder(void *arg) { thread_fn(arg); return NULL; }
static void *kthread_run(int (*fn)(void *), void *arg, const char *name)
{
	if (fail_thread)
		return NULL;
	thread_fn = fn;
	assert(!pthread_create(&holder, NULL, run_holder, arg));
	return &holder;
}
#include "native_shutdown_fault.h"
#endif
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
	host_instance = &parent;
	mk_parent_endpoint = NULL;
	mk_halt_notice.value = 0;
	sends = cas_calls = 0;
	irq_disabled = false;
	mk_receiver_ready = mk_halt_quiesced = mk_overlay_mutex = false;
	spawn = true;
	panicking = kexec_in_progress = false;
	overlay_attempts = 0;
	cpuhp_result = 0;
	registered = NULL;
	system_state = SYSTEM_HALT;
}

static void ready(void)
{
	reset();
	assert(!mk_riscv_doorbell_init());
}

static void qualify(void)
{
	assert(registered && registered->ops->shutdown);
	registered->ops->shutdown(registered->data);
}

static void expect_no_notice(void)
{
	mk_riscv_notify_parent_halted();
	assert(!sends && !ring.ring.head.value && !mk_halt_notice.value && !cas_calls);
}

int main(void)
{
	struct mk_resource_ack ack;
	struct mk_message *msg;
	unsigned int i;
	const enum system_states terminal[] = { SYSTEM_HALT, SYSTEM_POWER_OFF, SYSTEM_RESTART };

	/* A direct/emergency machine-stop must not authorize reusable settlement. */
	ready();
	expect_no_notice();
	system_state = SYSTEM_RESTART;
	expect_no_notice();
	for (i = 0; i < sizeof(terminal) / sizeof(*terminal); i++) {
		ready();
		system_state = terminal[i];
		qualify();
		assert(mk_overlay_mutex && overlay_attempts == 1);
		mk_riscv_notify_parent_halted();
		assert(sends == 1 && ring.ring.head.value == 1);
	}
	ready();
	panicking = true;
	qualify();
	assert(!overlay_attempts && !mk_overlay_mutex);
	expect_no_notice();
	ready();
	kexec_in_progress = true;
	system_state = SYSTEM_RESTART;
	qualify();
	assert(!overlay_attempts && !mk_overlay_mutex);
	expect_no_notice();
	ready();
	system_state = SYSTEM_RUNNING;
	qualify();
	assert(!overlay_attempts);
	expect_no_notice();
	ready();
	mk_overlay_mutex = true;
	qualify();
	assert(overlay_attempts == 1 && mk_overlay_mutex);
	expect_no_notice();
	ready();
	qualify();
	panicking = true;
	expect_no_notice();
	assert(mk_overlay_mutex);
	reset();
	spawn = false;
	assert(!mk_riscv_doorbell_init() && !registered);
	expect_no_notice();
	reset();
	cpuhp_result = -EIO;
	assert(mk_riscv_doorbell_init() == -EIO && !registered);
	expect_no_notice();

	ready();
	qualify();
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
	ready();
	qualify();
	parent.ipi_lock = true;
	mk_riscv_notify_parent_halted();
	assert(!sends && !ring.ring.head.value && parent.ipi_lock && !irq_disabled);
	ready();
	qualify();
	ring.ring.head.value = 63;
	mk_riscv_notify_parent_halted();
	assert(!sends && ring.ring.head.value == 63 && !parent.ipi_lock);
	ready();
	qualify();
	parent.ipi_data = NULL;
	mk_riscv_notify_parent_halted();
	assert(!sends && !parent.ipi_lock);
	ready();
	qualify();
	mk_parent_endpoint = NULL;
	mk_riscv_notify_parent_halted();
	assert(!sends);
#ifdef MK_NATIVE_TEST_KERNEL
	/* Default-off/host/wrong-instance gates must never create a holder. */
	assert(mk_test_shutdown_setup("bad") == 0);
	assert(mk_test_shutdown_setup("1") == 1);
	ready();
	spawn = false;
	qualify();
	assert(!contention_proofs && !contention_failures);
	ready();
	self.id = 2;
	qualify();
	assert(!contention_proofs && !contention_failures);
	self.id = 1;
	ready();
	fail_thread = true;
	qualify();
	expect_no_notice();
	assert(contention_failures == 1 && !mk_overlay_mutex);
	fail_thread = false;
	ready();
	qualify();
	assert(!pthread_join(holder, NULL));
	assert(contention_proofs == 1 && contention_failures == 1);
	assert(overlay_attempts == 2 && !mk_overlay_mutex);
	expect_no_notice();
#endif
	puts("PASS: qualified normal shutdown only; panic/kexec/contention retain; bounded notice");
	return 0;
}
