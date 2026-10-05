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
static struct rcu_probe_event events[32];
static atomic_t sequence = ATOMIC_INIT(0), invocations = ATOMIC_INIT(0);
static atomic_t consumed = ATOMIC_INIT(0);
static struct mk_ipi_handler *selected;
static struct rcu_probe_context *context;
/* Observer retains only the test task, never the handler or its context. */
static struct task_struct *waiter;
static u64 cookie;
static bool used, entered, released, timed_out, done, overflow;
/* 0: raw IPI unregister, 1: message replacement, 2: terminal cleanup. */
static unsigned int registry_mode;
static void *type_context;
static struct task_struct *registrar;
static bool detached, registration_done;
static int registration_result;
static atomic_t replacement_invocations = ATOMIC_INIT(0);

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
	size_t expected = sizeof(value) + (registry_mode ? sizeof(struct mk_message) : 0);

	if (!READ_ONCE(used) || type != MK_MSG_USER || size != expected)
		return;
	if (value != READ_ONCE(cookie))
		return;
	atomic_inc(&consumed);
	record(8);
}

u64 mk_native_rcu_tag(struct mk_ipi_data *data)
{
	struct mk_message *message = (void *)data->buffer;
	u64 value = 0;

	if (!READ_ONCE(used) || data->type != MK_MSG_USER)
		return 0;
	if (!registry_mode && data->data_size == sizeof(value))
		memcpy(&value, data->buffer, sizeof(value));
	else if (registry_mode && data->data_size == sizeof(*message) + sizeof(value) &&
		 message->payload_len == sizeof(value) && message->msg_type == MK_MSG_USER)
		memcpy(&value, message->payload, sizeof(value));
	return value;
}

static void callback_hold(u64 value, struct rcu_probe_context *ctx)
{
	u64 deadline = ktime_get_mono_fast_ns() + 2 * NSEC_PER_SEC;

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

static void callback(struct mk_ipi_data *data, void *opaque)
{
	u64 value;

	if (data->data_size != sizeof(value))
		return;
	memcpy(&value, data->buffer, sizeof(value));
	callback_hold(value, opaque);
}

static void message_callback(u32 type, u32 subtype, u64 id,
			     void *payload, u32 length, void *ctx)
{
	u64 value;

	if (type != MK_MSG_USER || length != sizeof(value))
		return;
	memcpy(&value, payload, sizeof(value));
	callback_hold(value, ctx);
}

static void replacement_callback(u32 type, u32 subtype, u64 id,
				 void *payload, u32 length, void *ctx)
{
	u64 value;

	if (type != MK_MSG_USER || length != sizeof(value))
		return;
	memcpy(&value, payload, sizeof(value));
	if (value == cookie) {
		atomic_inc(&replacement_invocations);
		record(15);
	}
}

void mk_native_registry_published(void *ctx, struct mk_ipi_handler *handler, void *type)
{
	if (registry_mode && ctx == context && !selected) {
		selected = handler;
		type_context = type;
	}
}

void mk_native_registry_detached(bool terminal)
{
	if (current != waiter || !registry_mode || terminal != (registry_mode == 2))
		return;
	record(12);
	WRITE_ONCE(detached, true);
	wake_up(&callback_wait);
}

void mk_native_registry_freed(unsigned long identity)
{
	if (registry_mode && identity == (unsigned long)type_context)
		record(13);
}

bool mk_native_registry_lock(struct mutex *lock)
{
	if (!registry_mode || current != READ_ONCE(registrar))
		return false;
	/* Observe genuine contention, then use the normal native blocking lock. */
	if (!mutex_trylock(lock)) {
		record(11);
		mutex_lock(lock);
	} else {
		WRITE_ONCE(timed_out, true); /* No contested admission was exercised. */
	}
	return true;
}

static int registration_thread(void *unused)
{
	if (!wait_event_timeout(callback_wait, READ_ONCE(detached), 10 * HZ)) {
		WRITE_ONCE(timed_out, true);
		return 0;
	}
	registration_result = mk_register_msg_handler(MK_MSG_USER, replacement_callback, NULL);
	record(14);
	smp_store_release(&registration_done, true);
	return 0;
}

static int unregister_thread(void *unused)
{
	if (!wait_event_timeout(callback_wait, READ_ONCE(entered), 10 * HZ))
		WRITE_ONCE(timed_out, true);
	if (registry_mode == 2)
		mk_messaging_cleanup();
	else if (registry_mode == 1) {
		if (mk_unregister_msg_handler(MK_MSG_USER, message_callback))
			WRITE_ONCE(timed_out, true);
	} else
		multikernel_unregister_handler(selected);
	kfree(context);
	record(7);
	smp_store_release(&done, true);
	return 0;
}

static ssize_t registry_arm_write(struct file *file, const char __user *data,
				  size_t count, loff_t *position)
{
	char buffer[64], extra;
	unsigned int mode;
	u64 value;
	int ret;

	if (!count || count >= sizeof(buffer) || *position)
		return -EINVAL;
	if (copy_from_user(buffer, data, count))
		return -EFAULT;
	buffer[count] = '\0';
	if (sscanf(buffer, "%u %llx %c", &mode, &value, &extra) != 2 || !value || mode < 1 || mode > 2)
		return -EINVAL;
	guard(mutex)(&control_lock);
	if (mk_self->id || used || !cpu_online(0) || !cpu_online(1) || !cpu_online(2))
		return -EBUSY;
	context = kzalloc(sizeof(*context), GFP_KERNEL);
	if (!context)
		return -ENOMEM;
	cookie = context->cookie = value;
	registry_mode = mode;
	used = true;
	waiter = kthread_create(unregister_thread, NULL, "mk-reg-retire");
	if (IS_ERR(waiter)) {
		ret = PTR_ERR(waiter);
		waiter = NULL;
		goto free_context;
	}
	registrar = kthread_create(registration_thread, NULL, "mk-reg-insert");
	if (IS_ERR(registrar)) {
		ret = PTR_ERR(registrar);
		registrar = NULL;
		goto stop_waiter;
	}
	ret = mk_register_msg_handler(MK_MSG_USER, message_callback, context);
	if (ret)
		goto stop_registrar;
	get_task_struct(waiter);
	get_task_struct(registrar);
	kthread_bind(waiter, 1);
	kthread_bind(registrar, 1);
	wake_up_process(waiter);
	wake_up_process(registrar);
	return count;
stop_registrar:
	kthread_stop(registrar);
	registrar = NULL;
stop_waiter:
	kthread_stop(waiter);
	waiter = NULL;
free_context:
	kfree(context);
	WRITE_ONCE(timed_out, true);
	return ret;
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

static ssize_t registry_send_write(struct file *file, const char __user *data,
				   size_t count, loff_t *position)
{
	u64 value;
	int ret;

	if (*position || !count || count > 16 || mk_self->id != 1)
		return -EINVAL;
	ret = kstrtou64_from_user(data, count, 16, &value);
	if (ret || !value)
		return ret ?: -EINVAL;
	ret = mk_send_message(0, MK_MSG_USER, 0, &value, sizeof(value));
	return ret ?: count;
}

static int status_show(struct seq_file *seq, void *unused)
{
	unsigned int i;
	bool first = true, finished = smp_load_acquire(&done);
	bool sleeping = waiter && !finished &&
		(READ_ONCE(waiter->__state) & (TASK_INTERRUPTIBLE | TASK_UNINTERRUPTIBLE));

	seq_printf(seq, "{\"mode\":%u,\"type_context\":\"%px\",\"registration_done\":%s,\"registration_result\":%d,\"replacement_invocations\":%d,\"registrar_sleeping\":%s,",
		registry_mode, type_context, smp_load_acquire(&registration_done) ? "true" : "false",
		READ_ONCE(registration_result), atomic_read(&replacement_invocations),
		registrar && !READ_ONCE(registration_done) &&
		(READ_ONCE(registrar->__state) & (TASK_INTERRUPTIBLE | TASK_UNINTERRUPTIBLE)) ? "true" : "false");
	seq_printf(seq, "\"cookie\":\"%016llx\",\"handler\":\"%px\",\"context\":\"%px\",\"invocations\":%d,\"consumed\":%d,\"released\":%s,\"timed_out\":%s,\"waiter_sleeping\":%s,\"done\":%s,\"overflow\":%s,\"events\":[",
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
static const struct file_operations registry_arm_fops = { .owner = THIS_MODULE, .write = registry_arm_write };
static const struct file_operations registry_send_fops = { .owner = THIS_MODULE, .write = registry_send_write };

void mk_native_rcu_init(struct dentry *directory)
{
	debugfs_create_file("rcu_arm", 0200, directory, NULL, &arm_fops);
	debugfs_create_file("rcu_release", 0200, directory, NULL, &release_fops);
	debugfs_create_file("rcu_send", 0200, directory, NULL, &send_fops);
	debugfs_create_file("rcu_status", 0400, directory, NULL, &status_fops);
	debugfs_create_file("registry_arm", 0200, directory, NULL, &registry_arm_fops);
	debugfs_create_file("registry_send", 0200, directory, NULL, &registry_send_fops);
}
