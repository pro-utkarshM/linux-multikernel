// SPDX-License-Identifier: GPL-2.0-only
/* Pause at event publication and run the actual closer hook before resuming. */
#include <stdbool.h>
#include <stdio.h>

struct task_struct { int refs; } task;
struct work_struct { int unused; } work;
struct completion { int unused; } rx_done, worker_release;
static struct task_struct *current = &task, *closer;
static struct work_struct *selected_work;
static bool armed = true, worker_mode = true, selected_ready = true;
static bool entered, failed, closed;
static void *selected = &work;
#define HZ 100
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define smp_load_acquire(p) __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define smp_store_release(p, v) __atomic_store_n((p), (v), __ATOMIC_RELEASE)
#define get_task_struct(t) ((t)->refs++)
static int wait_for_completion_timeout(struct completion *done, int timeout)
{
	return 1;
}
void mk_native_tty_flush_begin(void *conn, struct work_struct *work);
static void record(unsigned int point)
{
	if (point == 10)
		mk_native_tty_flush_begin(selected, &work);
}
#include "tty-observation-production.h"

int main(void)
{
	if (!mk_native_tty_worker(selected) || failed || closer != current ||
	    selected_work != &work || task.refs != 1) {
		puts("FAIL: published worker event admitted closer before observer readiness");
		return 1;
	}
	puts("PASS: closer admitted at event publication sees initialized worker phase");
	return 0;
}
