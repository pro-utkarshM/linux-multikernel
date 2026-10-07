// SPDX-License-Identifier: GPL-2.0-only
/* Actual status function, controlled pthread/API boundaries; not native proof. */
#include <assert.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#define TASK_INTERRUPTIBLE 1
#define TASK_UNINTERRUPTIBLE 2
#define TASK_RUNNING 0
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
struct task_struct { unsigned int __state; } task;
struct rcu_probe_event { unsigned int sequence, point, cpu; bool hardirq, vector, ready; } events[32];
struct seq_file { char text[8192]; size_t used; } output;
static pthread_mutex_t control_lock __attribute__((unused)) = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t schedule_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t schedule_changed = PTHREAD_COND_INITIALIZER;
static bool contended_or_printing, unwind_mode, stale_mode;
static unsigned int stale_point;
static struct task_struct *waiter, *registrar;
static unsigned int registry_mode;
static void *type_context, *selected, *context, *observed_type_context;
static unsigned long long cookie;
static bool done, registration_done, released, timed_out, overflow;
static int registration_result, replacement_invocations, invocations, consumed;
#define atomic_read(p) (*(p))
#define smp_load_acquire(p) __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define READ_ONCE(x) ({ __auto_type p = &(x); __typeof__(x) value = *p; \
    if (stale_mode && (void *)p == (void *)&task.__state) { \
        task.__state = TASK_RUNNING; \
        events[0] = (struct rcu_probe_event){ .sequence=1, .point=stale_point, .ready=true }; \
    } value; })

static void notify_unwind(void)
{
    if (!unwind_mode)
        return;
    pthread_mutex_lock(&schedule_lock);
    contended_or_printing = true;
    pthread_cond_signal(&schedule_changed);
    pthread_mutex_unlock(&schedule_lock);
}

struct lock_guard { pthread_mutex_t *mutex; };
static struct lock_guard __attribute__((unused)) acquire_guard(pthread_mutex_t *mutex)
{
    if (pthread_mutex_trylock(mutex)) {
        notify_unwind();
        pthread_mutex_lock(mutex);
    }
    return (struct lock_guard){mutex};
}
static void __attribute__((unused)) release_guard(struct lock_guard *guard)
{
    pthread_mutex_unlock(guard->mutex);
}
#define guard(kind) struct lock_guard scope_guard __attribute__((cleanup(release_guard))) = acquire_guard

static void seq_printf(struct seq_file *seq, const char *format, ...)
{
    va_list args, copy;
    va_start(args, format);
    va_copy(copy, args);
    if (!strncmp(format, "{\"mode\":", 8)) {
        (void)va_arg(copy, unsigned int);
        observed_type_context = va_arg(copy, void *);
        notify_unwind();
    }
    va_end(copy);
    seq->used += vsnprintf(seq->text + seq->used, sizeof(seq->text) - seq->used, format, args);
    va_end(args);
    assert(seq->used < sizeof(seq->text));
}
static void seq_puts(struct seq_file *seq, const char *text)
{
    seq_printf(seq, "%s", text);
}
#include "observation-production.h"

static void *reader(void *unused)
{
    status_show(&output, NULL);
    return NULL;
}

int main(void)
{
    int failures = 0;
    unsigned int role;
    pthread_t thread;

    for (role = 0; role < 2; role++) {
        memset(&output, 0, sizeof(output));
        memset(events, 0, sizeof(events));
        waiter = role ? NULL : &task;
        registrar = role ? &task : NULL;
        stale_point = role ? 11 : 3;
        task.__state = TASK_INTERRUPTIBLE;
        stale_mode = true;
        status_show(&output, NULL);
        if (!strstr(output.text, role ? "\"registrar_sleeping\":false" : "\"waiter_sleeping\":false")) {
            puts("FAIL: initial callback-wait sleep combined with later boundary marker");
            failures++;
        }
        stale_mode = false;
        memset(&output, 0, sizeof(output));
        events[0] = (struct rcu_probe_event){ .sequence=1, .point=stale_point, .ready=true };
        task.__state = TASK_UNINTERRUPTIBLE;
        status_show(&output, NULL);
        if (!strstr(output.text, role ? "\"registrar_sleeping\":true" : "\"waiter_sleeping\":true")) {
            puts("FAIL: genuine post-boundary sleep not observable");
            failures++;
        }
    }

    memset(&output, 0, sizeof(output));
    unwind_mode = true;
    pthread_mutex_lock(&control_lock);
    type_context = &task; /* valid stand-in for transient setup; never dangling */
    assert(!pthread_create(&thread, NULL, reader, NULL));
    pthread_mutex_lock(&schedule_lock);
    while (!contended_or_printing)
        pthread_cond_wait(&schedule_changed, &schedule_lock);
    pthread_mutex_unlock(&schedule_lock);
    type_context = NULL;
    waiter = NULL;
    pthread_mutex_unlock(&control_lock);
    pthread_join(thread, NULL);
    if (observed_type_context) {
        puts("FAIL: status exposed transient setup before arm unwind finished");
        failures++;
    }
    printf("Native observation: %d failures (controlled API boundaries, not native IRQ proof)\n", failures);
    return !!failures;
}
