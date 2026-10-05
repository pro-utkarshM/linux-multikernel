// SPDX-License-Identifier: GPL-2.0-only
/* Disposable VM: sender's actual lookup reference versus instance removal. */
#include <linux/debugfs.h>
#include <linux/interrupt.h>
#include <linux/kexec.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/multikernel.h>
#include <linux/mutex.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <asm/multikernel_test.h>

struct destroy_event { unsigned int seq, point, cpu; bool hardirq, irqs_off, ready; };
static struct destroy_event events[16];
static atomic_t sequence = ATOMIC_INIT(0);
static DEFINE_MUTEX(control_lock);
static DECLARE_WAIT_QUEUE_HEAD(release_wait);
static struct task_struct *sender;
static unsigned long selected, selected_image, pool;
static u64 cookie, ring, manifest;
static int send_result, probe_result;
static bool armed, entered, released, failed, retired, sent, probed;

static void record(unsigned int point)
{
	unsigned int index = atomic_inc_return(&sequence) - 1;
	struct destroy_event *event;

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

void mk_native_destroy_hold(struct mk_instance *instance, void *data, size_t size)
{
	u64 value;

	if (!smp_load_acquire(&armed) || current != sender || size != sizeof(value) || !data)
		return;
	memcpy(&value, data, sizeof(value));
	if (value != cookie)
		return;
	if (entered || instance->id != 1 || instance->state != MK_STATE_LOADED ||
	    !instance->kimage || !instance->ipi_phys || !instance->manifest_phys || !instance->instance_pool) {
		WRITE_ONCE(failed, true);
		return;
	}
	selected = (unsigned long)instance;
	selected_image = (unsigned long)instance->kimage;
	ring = instance->ipi_phys;
	manifest = instance->manifest_phys;
	pool = (unsigned long)instance->instance_pool;
	record(1); /* after real doorbell, no spinlock; original lookup ref only */
	smp_store_release(&entered, true);
	if (!wait_event_timeout(release_wait, smp_load_acquire(&released), 30 * HZ))
		WRITE_ONCE(failed, true);
	record(7); /* next production operation drops the actual sender ref */
}

void mk_native_destroy_boundary(unsigned long identity, unsigned int point)
{
	if (smp_load_acquire(&entered) && identity == selected)
		record(point);
}

void mk_native_destroy_retired(struct mk_instance *instance)
{
	if (!smp_load_acquire(&entered) || (unsigned long)instance != selected)
		return;
	/* kref kept this record, NOT its retired pool/control allocations. */
	if (instance->state != MK_STATE_READY || instance->kimage || instance->instance_pool ||
	    instance->ctrl_va || instance->region_count || !mk_cpu_set_empty(instance->cpus) ||
	    instance->ipi_phys != ring || instance->manifest_phys != manifest)
		WRITE_ONCE(failed, true);
	WRITE_ONCE(retired, true);
	record(5);
}

static int sender_thread(void *unused)
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
	task = kthread_create(sender_thread, NULL, "mk-native-ref");
	if (IS_ERR(task))
		return PTR_ERR(task);
	kthread_bind(task, 0);
	sender = task;
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
	record(6);
	smp_store_release(&released, true);
	wake_up_all(&release_wait);
	return count;
}

static ssize_t probe_write(struct file *file, const char __user *data,
			   size_t count, loff_t *position)
{
	char value;

	if (count != 1 || *position || copy_from_user(&value, data, 1) || value != '1')
		return -EINVAL;
	guard(mutex)(&control_lock);
	if (!smp_load_acquire(&entered) || released || probed)
		return -EINVAL;
	WRITE_ONCE(probe_result, multikernel_send_ipi_data(1, &cookie, sizeof(cookie), MK_MSG_USER));
	smp_store_release(&probed, true);
	return count;
}

static int status_show(struct seq_file *seq, void *unused)
{
	unsigned int i;
	bool inside = smp_load_acquire(&entered), first = true;

	seq_printf(seq, "{\"cookie\":\"%016llx\",\"instance\":\"%lx\",\"image\":\"%lx\",\"ring\":\"%llx\",\"manifest\":\"%llx\",\"pool\":\"%lx\",\"released\":%s,\"failed\":%s,\"retired\":%s,\"sent\":%s,\"send_result\":%d,\"probed\":%s,\"probe_result\":%d,\"events\":[",
		READ_ONCE(cookie), inside ? selected : 0, inside ? selected_image : 0,
		inside ? ring : 0, inside ? manifest : 0, inside ? pool : 0,
		READ_ONCE(released) ? "true" : "false", READ_ONCE(failed) ? "true" : "false",
		READ_ONCE(retired) ? "true" : "false", smp_load_acquire(&sent) ? "true" : "false",
		READ_ONCE(send_result), smp_load_acquire(&probed) ? "true" : "false", READ_ONCE(probe_result));
	for (i = 0; i < ARRAY_SIZE(events); i++) {
		struct destroy_event *e = &events[i];

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

void mk_native_destroy_init(struct dentry *directory)
{
	debugfs_create_file("destroy_arm", 0200, directory, NULL, &arm_fops);
	debugfs_create_file("destroy_release", 0200, directory, NULL, &release_fops);
	debugfs_create_file("destroy_probe", 0200, directory, NULL, &probe_fops);
	debugfs_create_file("destroy_status", 0400, directory, NULL, &status_fops);
}
