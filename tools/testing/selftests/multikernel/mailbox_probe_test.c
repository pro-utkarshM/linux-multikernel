// SPDX-License-Identifier: GPL-2.0-only
/* Real private probe admission; architecture calls/time are modeled, not a VM. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef uint64_t u64;
typedef uint64_t ktime_t;
#define U64_MAX UINT64_MAX
#define U32_MAX UINT32_MAX
#define MK_SLOT_IDLE 0
#define MK_SLOT_QUARANTINED 4
#define MK_STATE_ACTIVE 3
#define READ_ONCE(x) (x)
#define atomic64_read(x) (*(x))
struct slot { unsigned int ready; } context, pool_context;
struct cpu_set { u64 id; } assigned = {256}, tracked = {256};
struct mk_instance {
	unsigned int id, state;
	struct cpu_set *cpus, *cpus_on_slot;
	struct { struct slot *spawn_ctx; } arch;
} instance, self, *mk_self = &self;
struct pool { struct { struct slot *slot; } arch; } pool, *mk_pool = &pool;
static bool enabled, safe_vm, probe_used, found;
static u64 fail_cpu, failure_count, probe_cpu, probe_elapsed_us;
static int probe_result, probe_retry, probe_repark;
static unsigned int calls, reparks, references, clock_calls;
static int mk_overlay_mutex, locked, first_result;
struct lock_guard { int *address; };
static struct lock_guard lock(int *address)
{
	assert(!locked++);
	return (struct lock_guard){address};
}
static void unlock(struct lock_guard *held)
{
	assert(held->address == &mk_overlay_mutex && locked == 1);
	locked--;
}
#define guard(kind) struct lock_guard held __attribute__((cleanup(unlock))) = lock
static struct mk_instance *mk_instance_find(int id)
{
	assert(locked && id == 1);
	if (!found)
		return NULL;
	references++;
	return &instance;
}
static void mk_instance_put(struct mk_instance *value)
{
	assert(locked && value == &instance && references == 1);
	references--;
}
static bool mk_cpu_set_contains(struct cpu_set *set, u64 cpu)
{
	return set && set->id == cpu;
}
static ktime_t ktime_get(void) { return clock_calls++ ? 2000001 : 1000000; }
static u64 ktime_us_delta(ktime_t end, ktime_t start) { return end - start; }
static int mk_arch_confirm_parked(struct mk_instance *value, u64 cpu)
{
	assert(locked && references == 1 && value == &instance && cpu == 256);
	if (++calls == 1) {
		assert(probe_used && probe_cpu == cpu);
		if (first_result == -ETIMEDOUT) {
			context.ready = MK_SLOT_QUARANTINED;
			pool_context.ready = MK_SLOT_QUARANTINED;
		}
		return first_result;
	}
	return -EBUSY;
}
static int mk_repark_instance_to_host(struct mk_instance *value)
{
	assert(locked && references == 1 && value == &instance);
	reparks++;
	return -EBUSY;
}
#include "probe.h"

static void reset(void)
{
	assert(!locked && !references);
	enabled = safe_vm = found = true;
	probe_used = false;
	fail_cpu = probe_cpu = U64_MAX;
	failure_count = calls = reparks = clock_calls = 0;
	probe_result = probe_retry = probe_repark = 0;
	probe_elapsed_us = 0;
	first_result = -ETIMEDOUT;
	context.ready = pool_context.ready = MK_SLOT_IDLE;
	self.id = 0;
	mk_self = &self;
	pool.arch.slot = &pool_context;
	mk_pool = &pool;
	instance = (struct mk_instance){.id = 1, .state = MK_STATE_ACTIVE,
		.cpus = &assigned, .cpus_on_slot = &tracked, .arch.spawn_ctx = &context};
}
static void refuse(int error)
{
	assert(mailbox_probe_set(NULL, 256) == error);
	assert(!calls && !reparks && !probe_used && !locked && !references);
}
int main(void)
{
	reset(); enabled = false; refuse(-EPERM);
	reset(); safe_vm = false; refuse(-EPERM);
	reset(); mk_self = NULL; refuse(-EPERM);
	reset(); self.id = 1; refuse(-EPERM);
	reset(); fail_cpu = 256; refuse(-EBUSY);
	reset(); failure_count = 1; refuse(-EBUSY);
	reset(); found = false; refuse(-ENOENT);
	reset(); instance.state = 2; refuse(-EINVAL);
	reset(); instance.cpus = NULL; refuse(-EINVAL);
	reset(); instance.cpus_on_slot = NULL; refuse(-EINVAL);
	reset(); instance.arch.spawn_ctx = NULL; refuse(-EINVAL);
	reset(); mk_pool = NULL; refuse(-EINVAL);
	reset(); pool.arch.slot = NULL; refuse(-EINVAL);
	reset(); context.ready = MK_SLOT_QUARANTINED; refuse(-EBUSY);
	reset(); pool_context.ready = MK_SLOT_QUARANTINED; refuse(-EBUSY);
	reset(); assert(mailbox_probe_set(NULL, U64_MAX) == -EINVAL);
	assert(!calls && !references && !probe_used);
	reset(); assert(!mailbox_probe_set(NULL, 256));
	assert(probe_used && probe_cpu == 256 && probe_result == -ETIMEDOUT);
	assert(probe_retry == -EBUSY && probe_repark == -EBUSY);
	assert(probe_elapsed_us == 1000001 && calls == 2 && reparks == 1);
	assert(!locked && !references && !failure_count);
	assert(mailbox_probe_set(NULL, 256) == -EBUSY && calls == 2);
	reset(); first_result = 0; assert(!mailbox_probe_set(NULL, 256));
	assert(probe_result == 0 && calls == 1 && !reparks);
	puts("Mailbox probe: 18 admission/result scenarios passed (architecture modeled)");
	return 0;
}
