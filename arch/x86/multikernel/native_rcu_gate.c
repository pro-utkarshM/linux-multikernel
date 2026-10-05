// SPDX-License-Identifier: GPL-2.0-only
/* Disposable QEMU-only native IPI/RCU proof. No IRQ printing or sleeping. */
#include <linux/debugfs.h>
#include <linux/interrupt.h>
#include <linux/kthread.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/multikernel.h>
#include <linux/mutex.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <asm/multikernel_test.h>

struct rcu_probe_context { u64 cookie; };
struct rcu_probe_event {
	u32 sequence, point, cpu;
	bool hardirq, vector, ready;
};
static DEFINE_PER_CPU(bool, in_native_vector);
static DEFINE_MUTEX(control_lock);
static DECLARE_WAIT_QUEUE_HEAD(callback_wait);
static struct rcu_probe_event events[16];
static atomic_t sequence = ATOMIC_INIT(0), invocations = ATOMIC_INIT(0);
static atomic_t consumed = ATOMIC_INIT(0);
static struct mk_ipi_handler *selected;
static struct rcu_probe_context *context;
/* Observer retains only the test task, never the handler or its context. */
static struct task_struct *waiter;
static u64 cookie;
static bool used, entered, released, timed_out, done, overflow;

void mk_native_rcu_vector(bool value)
{
	this_cpu_write(in_native_vector, value);
}

static void record(unsigned int point)
{
	unsigned int index = atomic_inc_return(&sequence) - 1;
	struct rcu_probe_event *event;

	if (index >= ARRAY_SIZE(events)) {
		WRITE_ONCE(overflow, true);
		return;
	}
	event = &events[index];
	event->sequence = index + 1;
	event->point = point;
	/* Observation only, not a per-CPU access in preemptible context. */
	event->cpu = raw_smp_processor_id();
	event->hardirq = in_hardirq();
	event->vector = event->hardirq && this_cpu_read(in_native_vector);
	smp_store_release(&event->ready, true);
}

void mk_native_rcu_boundary(unsigned long handler, unsigned int point)
{
	if (handler == (unsigned long)READ_ONCE(selected))
		record(point);
}

void mk_native_rcu_consumed(unsigned int type, size_t size, u64 value)
{
	if (!READ_ONCE(used) || type != MK_MSG_USER || size != sizeof(value))
		return;
	if (value != READ_ONCE(cookie))
		return;
	atomic_inc(&consumed);
	record(8);
}

static void callback(struct mk_ipi_data *data, void *opaque)
{
	struct rcu_probe_context *ctx = opaque;
	u64 value, deadline = ktime_get_mono_fast_ns() + 2 * NSEC_PER_SEC;

	if (data->data_size != sizeof(value))
		return;
	memcpy(&value, data->buffer, sizeof(value));
	if (value != READ_ONCE(ctx->cookie))
		return;
	atomic_inc(&invocations);
	record(1);
	WRITE_ONCE(entered, true);
	wake_up(&callback_wait);
	while (!smp_load_acquire(&released)) {
		if (ktime_get_mono_fast_ns() >= deadline) {
			WRITE_ONCE(timed_out, true);
			record(10);
			break;
		}
		cpu_relax();
	}
	/* Last real context access before returning to the RCU dispatcher. */
	if (READ_ONCE(ctx->cookie) != value)
		WRITE_ONCE(timed_out, true);
	record(4);
}

static int unregister_thread(void *unused)
{
	if (!wait_event_timeout(callback_wait, READ_ONCE(entered), 10 * HZ))
		WRITE_ONCE(timed_out, true);
	multikernel_unregister_handler(selected);
	kfree(context);
	record(7);
	smp_store_release(&done, true);
	return 0;
}

static ssize_t arm_write(struct file *file, const char __user *data,
			 size_t count, loff_t *position)
{
	u64 value;
	int ret;

	if (*position || !count || count > 16)
		return -EINVAL;
	ret = kstrtou64_from_user(data, count, 16, &value);
	if (ret || !value)
		return ret ?: -EINVAL;
	guard(mutex)(&control_lock);
	if (mk_self->id || used || !cpu_online(0) || !cpu_online(1) || !cpu_online(2))
		return -EBUSY;
	context = kzalloc(sizeof(*context), GFP_KERNEL);
	if (!context)
		return -ENOMEM;
	cookie = context->cookie = value;
	selected = multikernel_register_handler(callback, context, MK_MSG_USER);
	if (!selected) {
		kfree(context);
		return -ENOMEM;
	}
	WRITE_ONCE(used, true);
	waiter = kthread_create(unregister_thread, NULL, "mk-rcu-retire");
	if (IS_ERR(waiter)) {
		ret = PTR_ERR(waiter);
		waiter = NULL;
		multikernel_unregister_handler(selected);
		kfree(context);
		WRITE_ONCE(timed_out, true);
		return ret;
	}
	/* Task-only observation reference, retained in this one-shot disposable VM. */
	get_task_struct(waiter);
	kthread_bind(waiter, 1);
	wake_up_process(waiter);
	return count;
}

static ssize_t release_write(struct file *file, const char __user *data,
			     size_t count, loff_t *position)
{
	char value;

	if (count != 1 || *position || copy_from_user(&value, data, 1) || value != '1')
		return -EINVAL;
	guard(mutex)(&control_lock);
	if (!used || !READ_ONCE(entered) || released || raw_smp_processor_id() != 2)
		return -EINVAL;
	record(9);
	smp_store_release(&released, true);
	return count;
}

static ssize_t send_write(struct file *file, const char __user *data,
			 size_t count, loff_t *position)
{
	u64 value;
	int ret;

	if (*position || !count || count > 16 || mk_self->id != 1)
		return -EINVAL;
	ret = kstrtou64_from_user(data, count, 16, &value);
	if (ret || !value)
		return ret ?: -EINVAL;
	ret = multikernel_send_ipi_data(0, &value, sizeof(value), MK_MSG_USER);
	return ret ?: count;
}

static int status_show(struct seq_file *seq, void *unused)
{
	unsigned int i;
	bool first = true, finished = smp_load_acquire(&done);
	bool sleeping = waiter && !finished &&
		(READ_ONCE(waiter->__state) & (TASK_INTERRUPTIBLE | TASK_UNINTERRUPTIBLE));

	seq_printf(seq, "{\"cookie\":\"%016llx\",\"handler\":\"%px\",\"context\":\"%px\",\"invocations\":%d,\"consumed\":%d,\"released\":%s,\"timed_out\":%s,\"waiter_sleeping\":%s,\"done\":%s,\"overflow\":%s,\"events\":[",
		cookie, selected, context, atomic_read(&invocations), atomic_read(&consumed),
		READ_ONCE(released) ? "true" : "false", READ_ONCE(timed_out) ? "true" : "false",
		sleeping ? "true" : "false", finished ? "true" : "false",
		READ_ONCE(overflow) ? "true" : "false");
	for (i = 0; i < ARRAY_SIZE(events); i++) {
		struct rcu_probe_event *e = &events[i];

		if (!smp_load_acquire(&e->ready))
			continue;
		seq_printf(seq, "%s{\"seq\":%u,\"point\":%u,\"cpu\":%u,\"hardirq\":%s,\"vector\":%s}",
			first ? "" : ",", e->sequence, e->point, e->cpu,
			e->hardirq ? "true" : "false", e->vector ? "true" : "false");
		first = false;
	}
	seq_puts(seq, "]}\n");
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(status);
static const struct file_operations arm_fops = { .owner = THIS_MODULE, .write = arm_write };
static const struct file_operations release_fops = { .owner = THIS_MODULE, .write = release_write };
static const struct file_operations send_fops = { .owner = THIS_MODULE, .write = send_write };

void mk_native_rcu_init(struct dentry *directory)
{
	debugfs_create_file("rcu_arm", 0200, directory, NULL, &arm_fops);
	debugfs_create_file("rcu_release", 0200, directory, NULL, &release_fops);
	debugfs_create_file("rcu_send", 0200, directory, NULL, &send_fops);
	debugfs_create_file("rcu_status", 0400, directory, NULL, &status_fops);
}
