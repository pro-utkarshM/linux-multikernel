// SPDX-License-Identifier: GPL-2.0-only
/* Disposable VM observation only; not part of the production submission. */
#include <linux/debugfs.h>
#include <linux/dmi.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/multikernel.h>
#include <linux/mutex.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <asm/multikernel_test.h>

static bool enabled;

static int __init concurrency_setup(char *value)
{
	if (!strcmp(value, "1"))
		enabled = true;
	return 1;
}
__setup("mk_native_concurrency_test=", concurrency_setup);

static void snapshot_cpus(struct seq_file *seq, const struct mk_cpu_set *set)
{
	mk_phys_cpu_t id;
	unsigned int i;

	seq_putc(seq, '[');
	mk_cpu_set_for_each(i, id, set) {
		if (i)
			seq_putc(seq, ',');
		seq_printf(seq, "%llu", id);
	}
	seq_putc(seq, ']');
}

struct chunk_output {
	struct seq_file *seq;
	bool first;
};

static int snapshot_chunk(struct mk_pool_chunk *chunk, void *data)
{
	struct chunk_output *output = data;

	if (!output->first)
		seq_putc(output->seq, ',');
	seq_printf(output->seq, "[%llu,%llu]", (u64)chunk->res.start,
		   (u64)resource_size(&chunk->res));
	output->first = false;
	return 0;
}

static int local_snapshot_show(struct seq_file *seq, void *unused)
{
	struct chunk_output output = { .seq = seq, .first = true };

	/* This resource lock, not an instance reference, protects the allocations. */
	guard(mutex)(&mk_overlay_mutex);
	if (!mk_self)
		return -ENODEV;
	seq_printf(seq, "{\"instance\":%d,\"owned_cpus\":", mk_self->id);
	snapshot_cpus(seq, mk_self->cpus);
	seq_puts(seq, ",\"pool_cpus\":");
	snapshot_cpus(seq, mk_pool ? mk_pool->cpus : NULL);
	seq_printf(seq, ",\"slot\":\"%llx\",\"park\":\"%llx\",\"chunks\":[",
		   mk_pool ? (u64)mk_pool->arch.slot_phys : 0,
		   mk_pool ? (u64)mk_pool->arch.park_phys : 0);
	if (mk_pool)
		mk_pool_for_each_chunk(snapshot_chunk, &output);
	seq_puts(seq, "]}\n");
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(local_snapshot);

static int __init concurrency_init(void)
{
	struct dentry *directory;

	if (!enabled || !mk_self)
		return 0;
	if (!dmi_match(DMI_SYS_VENDOR, "QEMU") ||
	    !dmi_match(DMI_PRODUCT_NAME, "Standard PC (Q35 + ICH9, 2009)"))
		return 0;
	directory = debugfs_create_dir("mk-native-concurrency-test", NULL);
	if (IS_ERR(directory))
		return PTR_ERR(directory);
	debugfs_create_file("local_snapshot", 0400, directory, NULL,
			    &local_snapshot_fops);
	mk_native_gate_init(directory);
	mk_native_rcu_init(directory);
	mk_native_tty_init(directory);
	return 0;
}
late_initcall(concurrency_init);
