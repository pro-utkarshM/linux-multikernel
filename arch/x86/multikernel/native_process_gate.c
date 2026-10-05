// SPDX-License-Identifier: GPL-2.0-only
/* Bounded process-only gates; not production code or IRQ/RCU qualification. */
#include <linux/debugfs.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/multikernel.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <asm/multikernel_test.h>

static bool available;
static DEFINE_RAW_SPINLOCK(event_lock);
static DECLARE_WAIT_QUEUE_HEAD(gate_wait);
struct native_event {
	u64 sequence, request, cpu;
	unsigned int point, operation;
	int result;
};
static struct native_event events[128];
static u64 sequence, gate_cpu;
static unsigned int event_count, armed, active_point, gate_seconds;
static bool gate_active, gate_released, overflow;

static void record_event(unsigned int point, u64 request, u64 cpu,
			 int result, unsigned int operation)
{
	struct native_event event = { .point = point, .request = request,
		.cpu = cpu, .result = result, .operation = operation };
	unsigned long flags;

	raw_spin_lock_irqsave(&event_lock, flags);
	event.sequence = ++sequence;
	if (event_count < ARRAY_SIZE(events))
		events[event_count++] = event;
	else
		overflow = true;
	raw_spin_unlock_irqrestore(&event_lock, flags);
	/* Only process-context callers, outside IRQ/raw-lock checkpoints. */
	pr_info("MK_X86_NATIVE {\"seq\":%llu,\"instance\":%d,\"point\":%u,\"request\":%llu,\"cpu\":%llu,\"result\":%d,\"operation\":%u}\n",
		event.sequence, mk_self->id, point, request, cpu, result, operation);
}

void mk_native_checkpoint(unsigned int point, u64 request, u64 cpu,
			  int result, unsigned int operation)
{
	unsigned long flags, timeout = 0;
	bool hold = false;

	if (!available)
		return;
	if (WARN_ON_ONCE(in_interrupt() || irqs_disabled()))
		return;
	record_event(point, request, cpu, result, operation);
	raw_spin_lock_irqsave(&event_lock, flags);
	if (armed == point && (point == MK_NATIVE_CONTROLLER_LOCKED || cpu == gate_cpu)) {
		armed = 0;
		active_point = point;
		gate_active = hold = true;
		gate_released = false;
		timeout = gate_seconds * HZ;
	}
	raw_spin_unlock_irqrestore(&event_lock, flags);
	if (!hold)
		return;
	record_event(MK_NATIVE_GATE_ENTER, request, cpu, point, operation);
	/* Timeout releases the hold but invalidates qualification. */
	timeout = wait_event_timeout(gate_wait, READ_ONCE(gate_released), timeout);
	record_event(timeout ? MK_NATIVE_GATE_LEAVE : MK_NATIVE_GATE_TIMEOUT,
		     request, cpu, timeout ? 0 : -ETIMEDOUT, operation);
	raw_spin_lock_irqsave(&event_lock, flags);
	gate_active = false;
	active_point = 0;
	raw_spin_unlock_irqrestore(&event_lock, flags);
}

static ssize_t gate_arm_write(struct file *file, const char __user *data,
			     size_t count, loff_t *position)
{
	char buffer[64], extra;
	unsigned int point, seconds;
	u64 cpu;
	unsigned long flags;
	int ret = count;

	if (!count || count >= sizeof(buffer) || *position)
		return -EINVAL;
	if (copy_from_user(buffer, data, count))
		return -EFAULT;
	buffer[count] = '\0';
	if (sscanf(buffer, "%u %llu %u %c", &point, &cpu, &seconds, &extra) != 3 ||
	    point < MK_NATIVE_CONTROLLER_LOCKED || point > MK_NATIVE_CPU_BEFORE_ACK ||
	    !seconds || seconds > 30)
		return -EINVAL;
	raw_spin_lock_irqsave(&event_lock, flags);
	if (gate_active || armed)
		ret = -EBUSY;
	else {
		armed = point;
		gate_cpu = cpu;
		gate_seconds = seconds;
	}
	raw_spin_unlock_irqrestore(&event_lock, flags);
	return ret;
}

static ssize_t gate_release_write(struct file *file, const char __user *data,
				 size_t count, loff_t *position)
{
	unsigned long flags;
	char value;

	if (count != 1 || *position || copy_from_user(&value, data, 1) || value != '1')
		return -EINVAL;
	raw_spin_lock_irqsave(&event_lock, flags);
	if (!gate_active) {
		raw_spin_unlock_irqrestore(&event_lock, flags);
		return -EINVAL;
	}
	gate_released = true;
	raw_spin_unlock_irqrestore(&event_lock, flags);
	wake_up_all(&gate_wait);
	return count;
}
static const struct file_operations gate_arm_fops = {
	.owner = THIS_MODULE, .write = gate_arm_write, .llseek = no_llseek,
};
static const struct file_operations gate_release_fops = {
	.owner = THIS_MODULE, .write = gate_release_write, .llseek = no_llseek,
};

static int events_show(struct seq_file *seq, void *unused)
{
	struct native_event *copy;
	unsigned long flags;
	unsigned int count, point, i;
	bool active, lost;

	copy = kmalloc_array(ARRAY_SIZE(events), sizeof(*copy), GFP_KERNEL);
	if (!copy)
		return -ENOMEM;
	raw_spin_lock_irqsave(&event_lock, flags);
	count = event_count;
	memcpy(copy, events, count * sizeof(*copy));
	active = gate_active;
	point = active_point;
	lost = overflow;
	raw_spin_unlock_irqrestore(&event_lock, flags);
	seq_printf(seq, "{\"active\":%s,\"point\":%u,\"overflow\":%s,\"events\":[",
		   active ? "true" : "false", point, lost ? "true" : "false");
	for (i = 0; i < count; i++) {
		struct native_event *event = &copy[i];
		seq_printf(seq, "%s{\"seq\":%llu,\"point\":%u,\"request\":%llu,\"cpu\":%llu,\"result\":%d,\"operation\":%u}",
			   i ? "," : "", event->sequence, event->point,
			   event->request, event->cpu, event->result, event->operation);
	}
	seq_puts(seq, "]}\n");
	kfree(copy);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(events);

void mk_native_gate_init(struct dentry *directory)
{
	/* Caller already checked default-off config, boot flag, self and QEMU DMI. */
	debugfs_create_file("events", 0400, directory, NULL, &events_fops);
	debugfs_create_file("gate_arm", 0200, directory, NULL, &gate_arm_fops);
	debugfs_create_file("gate_release", 0200, directory, NULL, &gate_release_fops);
	available = true;
}
