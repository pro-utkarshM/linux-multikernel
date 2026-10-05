// SPDX-License-Identifier: GPL-2.0-only
/* Actual callback notification paths; substituted completion/IRQ boundaries. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
typedef uint64_t u64;
#define NSEC_PER_SEC 1000000000ULL
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define smp_load_acquire(p) (*(p))
#define atomic_inc(p) (++*(p))
#define ktime_get_mono_fast_ns() 1ULL
#define cpu_relax() do { assert(false); } while (0)
#define DECLARE_WAIT_QUEUE_HEAD(name) int name
#define DECLARE_COMPLETION(name) unsigned int name
static bool hardirq, entered, detached, timed_out, released = true;
static unsigned int invocations, registry_mode = 1, signals, points[4], count;
static void *current = (void *)1, *waiter = (void *)1;
struct rcu_probe_context { u64 cookie; };
#define wake_up(p) do { assert(!hardirq); (*(p))++; signals++; } while (0)
#define complete(p) do { (*(p))++; signals++; } while (0)
static void record(unsigned int point) { assert(count < 4); points[count++] = point; }
#include "irq-wake-production.h"
int main(void)
{
    struct rcu_probe_context ctx = { .cookie = 42 };
    hardirq = true;
    callback_hold(42, &ctx);
    assert(entered && invocations == 1 && signals == 1 && !timed_out);
    hardirq = false;
    mk_native_registry_detached(false);
    assert(detached && signals == 2 && count == 3);
    assert(points[0] == 1 && points[1] == 4 && points[2] == 12);
    mk_native_registry_detached(true);
    assert(signals == 2); /* other mode must not release this observer */
    puts("native IRQ wake: callback and detached notification PASS (substituted boundaries)");
}
