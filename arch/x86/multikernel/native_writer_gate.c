// SPDX-License-Identifier: GPL-2.0-only
/* Disposable VM: real ring producer versus real loaded-Image unload. */
#include <linux/debugfs.h>
#include <linux/interrupt.h>
#include <linux/kexec.h>
#include <linux/kthread.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/multikernel.h>
#include <linux/mutex.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <asm/multikernel_test.h>

struct writer_event { unsigned int seq, point, cpu; bool hardirq, irqs_off, ready; };
static struct writer_event events[8];
static atomic_t sequence = ATOMIC_INIT(0);
static DEFINE_MUTEX(control_lock);
static struct task_struct *writer;
static unsigned long selected, selected_image;
static u64 cookie, ring;
static unsigned int segments;
static int send_result, probe_result;
static bool armed, entered, released, failed, sent, probed;

static void record(unsigned int point)
{
	unsigned int index = atomic_inc_return(&sequence) - 1;
	struct writer_event *event;

	if (index >= ARRAY_SIZE(events)) {
		WRITE_ONCE(failed, true);
		return;
	}
	event = &events[index];
	event->seq = index + 1;
	event->point = point;
	event->cpu = raw_smp_processor_id();
	event->hardirq = in_hardirq();
	event->irqs_off = irqs_disabled();
	smp_store_release(&event->ready, true);
}

void mk_native_writer_claim(struct mk_instance *instance, void *data, size_t size)
{
	u64 value, deadline;

	if (!smp_load_acquire(&armed) || current != writer || size != sizeof(value) || !data)
		return;
	memcpy(&value, data, sizeof(value));
	if (value != cookie)
		return;
	if (entered || instance->id != 1 || instance->state != MK_STATE_LOADED ||
	    !instance->kimage || !instance->kimage->nr_segments || !instance->ipi_phys) {
		WRITE_ONCE(failed, true);
		return;
	}
	selected = (unsigned long)instance;
	selected_image = (unsigned long)instance->kimage;
	ring = instance->ipi_phys;
	segments = instance->kimage->nr_segments;
	record(1); /* claimed actual slot, ipi_lock still held */
	smp_store_release(&entered, true);
	deadline = ktime_get_mono_fast_ns() + 2 * NSEC_PER_SEC;
	while (!smp_load_acquire(&released)) {
		if (ktime_get_mono_fast_ns() >= deadline) {
			WRITE_ONCE(failed, true);
			break;
		}
		cpu_relax();
	}
}

bool mk_native_writer_deactivate_lock(struct mk_instance *instance, unsigned long *flags)
{
	if (!smp_load_acquire(&entered) || (unsigned long)instance != selected)
		return false;
	if (!raw_spin_trylock_irqsave(&instance->ipi_lock, *flags)) {
		record(2); /* actual contention, before normal acquisition */
		raw_spin_lock_irqsave(&instance->ipi_lock, *flags);
	} else {
		WRITE_ONCE(failed, true);
	}
	return true;
}

void mk_native_writer_boundary(struct mk_instance *instance, unsigned int point)
{
	if (smp_load_acquire(&entered) && (unsigned long)instance == selected)
		record(point);
}

void mk_native_writer_segments(struct mk_instance *instance, struct kimage *image)
{
	if (smp_load_acquire(&entered) && (unsigned long)instance == selected &&
	    (unsigned long)image == selected_image)
		record(6); /* all actual segment returns completed */
}

static int writer_thread(void *unused)
{
	WRITE_ONCE(send_result, multikernel_send_ipi_data(1, &cookie, sizeof(cookie), MK_MSG_USER));
	smp_store_release(&sent, true);
	return 0;
}

static ssize_t arm_write(struct file *file, const char __user *data,
			 size_t count, loff_t *position)
{
	struct task_struct *task;
	u64 value;
	int ret;

	if (*position || !count || count > 16)
		return -EINVAL;
	ret = kstrtou64_from_user(data, count, 16, &value);
	if (ret || !value)
		return ret ?: -EINVAL;
	guard(mutex)(&control_lock);
	if (mk_self->id || armed || !cpu_online(0) || !cpu_online(1) || !cpu_online(2))
		return -EBUSY;
	task = kthread_create(writer_thread, NULL, "mk-native-writer");
	if (IS_ERR(task))
		return PTR_ERR(task);
	kthread_bind(task, 0);
	writer = task;
	cookie = value;
	smp_store_release(&armed, true);
	wake_up_process(task);
	return count;
}

static ssize_t release_write(struct file *file, const char __user *data,
			     size_t count, loff_t *position)
{
	char value;

	if (count != 1 || *position || copy_from_user(&value, data, 1) || value != '1')
		return -EINVAL;
	guard(mutex)(&control_lock);
	if (!smp_load_acquire(&entered) || released || raw_smp_processor_id() != 2)
		return -EINVAL;
	record(3);
	smp_store_release(&released, true);
	return count;
}

static ssize_t probe_write(struct file *file, const char __user *data,
			   size_t count, loff_t *position)
{
	char value;

	if (count != 1 || *position || copy_from_user(&value, data, 1) || value != '1')
		return -EINVAL;
	guard(mutex)(&control_lock);
	if (!smp_load_acquire(&sent) || probed)
		return -EINVAL;
	WRITE_ONCE(probe_result, multikernel_send_ipi_data(1, &cookie, sizeof(cookie), MK_MSG_USER));
	smp_store_release(&probed, true);
	return count;
}

static int status_show(struct seq_file *seq, void *unused)
{
	unsigned int i;
	bool inside = smp_load_acquire(&entered), first = true;

	seq_printf(seq, "{\"cookie\":\"%016llx\",\"instance\":\"%lx\",\"image\":\"%lx\",\"ring\":\"%llx\",\"segments\":%u,\"released\":%s,\"failed\":%s,\"sent\":%s,\"send_result\":%d,\"probed\":%s,\"probe_result\":%d,\"events\":[",
		READ_ONCE(cookie), inside ? selected : 0, inside ? selected_image : 0,
		inside ? ring : 0, inside ? segments : 0, READ_ONCE(released) ? "true" : "false",
		READ_ONCE(failed) ? "true" : "false", smp_load_acquire(&sent) ? "true" : "false",
		READ_ONCE(send_result), smp_load_acquire(&probed) ? "true" : "false", READ_ONCE(probe_result));
	for (i = 0; i < ARRAY_SIZE(events); i++) {
		struct writer_event *e = &events[i];

		if (!smp_load_acquire(&e->ready))
			continue;
		seq_printf(seq, "%s{\"seq\":%u,\"point\":%u,\"cpu\":%u,\"hardirq\":%s,\"irqs_off\":%s}",
			first ? "" : ",", e->seq, e->point, e->cpu,
			e->hardirq ? "true" : "false", e->irqs_off ? "true" : "false");
		first = false;
	}
	seq_puts(seq, "]}\n");
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(status);
static const struct file_operations arm_fops = { .owner = THIS_MODULE, .write = arm_write };
static const struct file_operations release_fops = { .owner = THIS_MODULE, .write = release_write };
static const struct file_operations probe_fops = { .owner = THIS_MODULE, .write = probe_write };

void mk_native_writer_init(struct dentry *directory)
{
	debugfs_create_file("writer_arm", 0200, directory, NULL, &arm_fops);
	debugfs_create_file("writer_release", 0200, directory, NULL, &release_fops);
	debugfs_create_file("writer_probe", 0200, directory, NULL, &probe_fops);
	debugfs_create_file("writer_status", 0400, directory, NULL, &status_fops);
}
