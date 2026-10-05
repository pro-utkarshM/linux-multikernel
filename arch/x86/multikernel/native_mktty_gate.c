// SPDX-License-Identifier: GPL-2.0-only
/* One-shot disposable VM: actual MKTTY receive versus final file release. */
#include <linux/debugfs.h>
#include <linux/interrupt.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/multikernel.h>
#include <linux/mutex.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <asm/multikernel_test.h>

struct tty_event { unsigned int seq, point, cpu; bool hardirq, vector, ready; };
static struct tty_event events[12];
static atomic_t sequence = ATOMIC_INIT(0);
static DEFINE_MUTEX(control_lock);
static u64 cookie;
static void *selected, *selected_buffer;
static char token[32];
static size_t token_len;
static bool armed, entered, released, failed, closed, unmatched;

static void record(unsigned int point)
{
	unsigned int index = atomic_inc_return(&sequence) - 1;
	struct tty_event *event;

	if (index >= ARRAY_SIZE(events)) {
		WRITE_ONCE(failed, true);
		return;
	}
	event = &events[index];
	event->seq = index + 1;
	event->point = point;
	event->cpu = raw_smp_processor_id();
	event->hardirq = in_hardirq();
	event->vector = mk_native_in_vector();
	smp_store_release(&event->ready, true);
}

void mk_native_tty_receive(void *conn, void *buffer, u32 id, const char *data, size_t size)
{
	u64 deadline;

	if (!smp_load_acquire(&armed) || id != 1 || size != token_len || memcmp(data, token, size))
		return;
	if (READ_ONCE(entered)) {
		if (conn || !smp_load_acquire(&closed) || READ_ONCE(unmatched))
			WRITE_ONCE(failed, true);
		record(9);
		WRITE_ONCE(unmatched, true);
		return;
	}
	if (!conn || !buffer) {
		WRITE_ONCE(failed, true);
		return;
	}
	selected = conn;
	selected_buffer = buffer;
	record(1);
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

bool mk_native_tty_close_lock(void *conn, raw_spinlock_t *lock, unsigned long *flags)
{
	if (!smp_load_acquire(&entered) || READ_ONCE(closed) || conn != selected)
		return false;
	if (!raw_spin_trylock_irqsave(lock, *flags)) {
		record(2); /* real failed acquisition, not a closer-start marker */
		raw_spin_lock_irqsave(lock, *flags);
	} else {
		WRITE_ONCE(failed, true);
	}
	record(5);
	return true;
}

void mk_native_tty_boundary(unsigned long identity, unsigned int point)
{
	if (!smp_load_acquire(&entered) || READ_ONCE(closed) || identity != (unsigned long)selected)
		return;
	record(point);
	if (point == 8)
		smp_store_release(&closed, true);
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
	if (mk_self->id || armed || !cpu_online(0) || !cpu_online(1) || !cpu_online(2))
		return -EBUSY;
	cookie = value;
	token_len = scnprintf(token, sizeof(token), "MKTTY_GATE_%016llx", value);
	smp_store_release(&armed, true);
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

static int status_show(struct seq_file *seq, void *unused)
{
	unsigned int i;
	bool inside = smp_load_acquire(&entered), first = true;

	seq_printf(seq, "{\"cookie\":\"%016llx\",\"connection\":\"%px\",\"buffer\":\"%px\",\"released\":%s,\"failed\":%s,\"closed\":%s,\"unmatched\":%u,\"events\":[",
		cookie, inside ? selected : NULL, inside ? selected_buffer : NULL,
		READ_ONCE(released) ? "true" : "false", READ_ONCE(failed) ? "true" : "false",
		smp_load_acquire(&closed) ? "true" : "false", READ_ONCE(unmatched));
	for (i = 0; i < ARRAY_SIZE(events); i++) {
		struct tty_event *e = &events[i];

		if (!smp_load_acquire(&e->ready))
			continue;
		seq_printf(seq, "%s{\"seq\":%u,\"point\":%u,\"cpu\":%u,\"hardirq\":%s,\"vector\":%s}",
			first ? "" : ",", e->seq, e->point, e->cpu,
			e->hardirq ? "true" : "false", e->vector ? "true" : "false");
		first = false;
	}
	seq_puts(seq, "]}\n");
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(status);
static const struct file_operations arm_fops = { .owner = THIS_MODULE, .write = arm_write };
static const struct file_operations release_fops = { .owner = THIS_MODULE, .write = release_write };

void mk_native_tty_init(struct dentry *directory)
{
	debugfs_create_file("tty_arm", 0200, directory, NULL, &arm_fops);
	debugfs_create_file("tty_release", 0200, directory, NULL, &release_fops);
	debugfs_create_file("tty_status", 0400, directory, NULL, &status_fops);
}
