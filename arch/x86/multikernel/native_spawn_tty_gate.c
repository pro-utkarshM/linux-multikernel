// SPDX-License-Identifier: GPL-2.0-only
/* Disposable QEMU instrumentation, never a production control interface. */
#include <linux/completion.h>
#include <linux/debugfs.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/multikernel.h>
#include <linux/mutex.h>
#include <linux/sched/task.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include <asm/multikernel_test.h>

static DEFINE_MUTEX(control);
static DEFINE_RAW_SPINLOCK(state_lock);
static DECLARE_COMPLETION(release_worker);
static struct work_struct *rx_work;
static struct task_struct *closer;
static struct completion *drain_done;
static bool available, armed, entered, released, failed, worker_done;
static bool drained, reopened, prepared, rx_irq = true;
static unsigned int mode, input, copied, dropped, peak, dequeued, discarded, inserted;
static u64 cookie;
struct spawn_event { unsigned int point, cpu; bool irq, vector; };
static struct spawn_event events[11];
static unsigned int nr_events;

static void record(unsigned int point)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&state_lock, flags);
	if (nr_events == ARRAY_SIZE(events)) {
		failed = true;
	} else {
		events[nr_events++] = (struct spawn_event) {
			.point = point, .cpu = raw_smp_processor_id(),
			.irq = in_hardirq(), .vector = mk_native_in_vector(),
		};
	}
	raw_spin_unlock_irqrestore(&state_lock, flags);
}

static void hold_worker(void)
{
	smp_store_release(&entered, true);
	record(2);
	if (!wait_for_completion_timeout(&release_worker, 15 * HZ))
		WRITE_ONCE(failed, true);
	record(9); /* actual continuation, including execution CPU after hotplug */
}

bool mk_native_spawn_tty_begin(struct work_struct *work)
{
	if (!READ_ONCE(available))
		return false;
	WRITE_ONCE(rx_work, work); /* static driver work item, valid for VM lifetime */
	if (!smp_load_acquire(&armed) || READ_ONCE(entered))
		return false;
	record(1);
	if (mode >= 3)
		hold_worker();
	return true;
}

void mk_native_spawn_tty_chunk(unsigned int count)
{
	unsigned long flags;

	if (!smp_load_acquire(&armed) || READ_ONCE(worker_done))
		return;
	raw_spin_lock_irqsave(&state_lock, flags);
	dequeued += count;
	raw_spin_unlock_irqrestore(&state_lock, flags);
	if (mode <= 2 && !READ_ONCE(entered))
		hold_worker(); /* TTY ref + bytes acquired, late flip insertion still pending */
}

void mk_native_spawn_tty_end(bool observed)
{
	if (!observed)
		return;
	record(6);
	smp_store_release(&worker_done, true);
}

void mk_native_spawn_tty_inserted(unsigned int count)
{
	unsigned long flags;

	if (!smp_load_acquire(&armed) || READ_ONCE(worker_done))
		return;
	raw_spin_lock_irqsave(&state_lock, flags);
	inserted += count;
	raw_spin_unlock_irqrestore(&state_lock, flags);
}

void mk_native_spawn_tty_hangup(bool flushed)
{
	if (smp_load_acquire(&armed) && mode == 2 && !READ_ONCE(reopened))
		record(flushed ? 11 : 10);
}

bool mk_native_spawn_tty_queue(struct work_struct *work)
{
	if (!smp_load_acquire(&armed) || mode != 4 || READ_ONCE(entered))
		return false;
	/* Explicit test-only placement. Ordinary delivery targets the first CPU. */
	schedule_work_on(2, work);
	return true;
}

void mk_native_spawn_tty_rx(unsigned int size, unsigned int accepted, unsigned int queued)
{
	unsigned long flags;

	if (!smp_load_acquire(&armed) || READ_ONCE(released))
		return;
	raw_spin_lock_irqsave(&state_lock, flags);
	input += size;
	copied += accepted;
	dropped += size - accepted;
	peak = max(peak, queued);
	rx_irq &= in_hardirq() && mk_native_in_vector();
	raw_spin_unlock_irqrestore(&state_lock, flags);
}

void mk_native_spawn_tty_shutdown(struct work_struct *work, bool done, unsigned int lost)
{
	if (!smp_load_acquire(&armed) || mode > 2 || READ_ONCE(drained))
		return;
	if (done) {
		WRITE_ONCE(discarded, lost);
		record(7);
		smp_store_release(&drained, true);
	} else {
		/* One-shot test retains this observer reference until VM termination. */
		get_task_struct(current);
		WRITE_ONCE(closer, current);
		if (work != READ_ONCE(rx_work))
			WRITE_ONCE(failed, true);
		record(3);
	}
}

void mk_native_spawn_tty_activate(void)
{
	if (!smp_load_acquire(&armed) || !smp_load_acquire(&drained) || READ_ONCE(reopened))
		return;
	record(8);
	smp_store_release(&reopened, true);
}

void mk_native_spawn_tty_barrier(struct work_struct *work, struct completion *done)
{
	if (current == READ_ONCE(closer) && work == READ_ONCE(rx_work))
		WRITE_ONCE(drain_done, done);
}

void mk_native_spawn_tty_wait(struct completion *done)
{
	if (current != READ_ONCE(closer) || done != READ_ONCE(drain_done) || READ_ONCE(prepared))
		return;
	record(4); /* actual uncompleted work-barrier completion, with waiter queued */
	smp_store_release(&prepared, true);
}

static ssize_t arm_write(struct file *file, const char __user *data,
			 size_t count, loff_t *position)
{
	char buf[20];
	unsigned int selected;
	u64 nonce;
	struct work_struct *work;

	if (*position || count != 18 || copy_from_user(buf, data, count))
		return -EINVAL;
	buf[count] = 0;
	if (buf[1] != ' ' || buf[0] < '1' || buf[0] > '4' || kstrtou64(buf + 2, 16, &nonce) || !nonce)
		return -EINVAL;
	selected = buf[0] - '0';
	guard(mutex)(&control);
	work = READ_ONCE(rx_work);
	if (!available || armed || !work || !cpu_online(1) || !cpu_online(2))
		return -EBUSY;
	/* Exclude the worker delivering this arm command from the selected run. */
	flush_work(work);
	mode = selected;
	cookie = nonce;
	smp_store_release(&armed, true);
	return count;
}

static ssize_t release_write(struct file *file, const char __user *data,
			     size_t count, loff_t *position)
{
	char value;

	if (*position || count != 1 || copy_from_user(&value, data, 1) || value != '1')
		return -EINVAL;
	guard(mutex)(&control);
	if (!smp_load_acquire(&entered) || released || worker_done)
		return -EINVAL;
	record(5);
	smp_store_release(&released, true);
	complete(&release_worker);
	return count;
}

static int status_show(struct seq_file *seq, void *unused)
{
	unsigned long flags;
	unsigned int i;
	bool waiting = smp_load_acquire(&prepared) && !smp_load_acquire(&released);

	waiting = waiting && (READ_ONCE(closer->__state) & TASK_UNINTERRUPTIBLE);
	raw_spin_lock_irqsave(&state_lock, flags);
	seq_printf(seq, "{\"mode\":%u,\"cookie\":\"%016llx\",\"work\":\"%px\","
		   "\"failed\":%s,\"released\":%s,\"worker_done\":%s,\"drained\":%s,"
		   "\"reopened\":%s,\"drain_waiting\":%s,\"input\":%u,\"copied\":%u,"
		   "\"dropped\":%u,\"peak\":%u,\"dequeued\":%u,\"discarded\":%u,\"inserted\":%u,\"rx_irq\":%s,\"events\":[",
		   mode, cookie, rx_work, READ_ONCE(failed) ? "true" : "false",
		   READ_ONCE(released) ? "true" : "false", smp_load_acquire(&worker_done) ? "true" : "false",
		   smp_load_acquire(&drained) ? "true" : "false", smp_load_acquire(&reopened) ? "true" : "false",
		   waiting ? "true" : "false", input, copied, dropped, peak, dequeued, discarded, inserted,
		   rx_irq ? "true" : "false");
	for (i = 0; i < nr_events; i++)
		seq_printf(seq, "%s{\"seq\":%u,\"point\":%u,\"cpu\":%u,\"hardirq\":%s,\"vector\":%s}",
			   i ? "," : "", i + 1, events[i].point, events[i].cpu,
			   events[i].irq ? "true" : "false", events[i].vector ? "true" : "false");
	seq_puts(seq, "]}\n");
	raw_spin_unlock_irqrestore(&state_lock, flags);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(status);
static const struct file_operations arm_fops = { .owner = THIS_MODULE, .write = arm_write };
static const struct file_operations release_fops = { .owner = THIS_MODULE, .write = release_write };

void mk_native_spawn_tty_init(struct dentry *directory)
{
	if (!mk_self || mk_self->id != 1)
		return;
	/* Caller already verified boot opt-in and QEMU q35 DMI identity. */
	WRITE_ONCE(available, true);
	debugfs_create_file("spawn_tty_arm", 0200, directory, NULL, &arm_fops);
	debugfs_create_file("spawn_tty_release", 0200, directory, NULL, &release_fops);
	debugfs_create_file("spawn_tty_status", 0400, directory, NULL, &status_fops);
}
