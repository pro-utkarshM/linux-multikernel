// SPDX-License-Identifier: GPL-2.0-only
/* Test-only VM instrumentation. Never include in the production series. */
#include <linux/debugfs.h>
#include <linux/init.h>
#include <linux/limits.h>
#include <linux/module.h>
#include <linux/multikernel.h>
#include <linux/mutex.h>
#include <linux/seq_file.h>
#include <linux/string.h>

static bool enabled;
static u64 fail_cpu = U64_MAX;

static int __init mk_native_confirm_setup(char *value)
{
	if (!strcmp(value, "1"))
		enabled = true;
	return 1;
}
__setup("mk_native_confirm_test=", mk_native_confirm_setup);

bool mk_x86_native_confirm_failure(u64 phys_cpu)
{
	/* Compare the physical ID directly: never use it as an array index. */
	if (!enabled || !mk_self || mk_self->id ||
	    phys_cpu != READ_ONCE(fail_cpu))
		return false;
	pr_info("MK_X86_TEST_CONFIRM_FAIL phys=%llu\n", phys_cpu);
	return true;
}

static int snapshot_show(struct seq_file *seq, void *unused)
{
	struct mk_instance *instance;

	/* The same resource lock pins these allocations, not just the reference. */
	guard(mutex)(&mk_overlay_mutex);
	instance = mk_instance_find(1);
	if (!instance)
		return -ENOENT;
	seq_printf(seq,
		   "{\"image\":\"%px\",\"ring\":\"%px\",\"ring_phys\":\"%llx\","
		   "\"control\":\"%llx\",\"context\":\"%llx\",\"pool\":\"%px\","
		   "\"pool_size\":%zu,\"state\":%u}\n",
		   instance->kimage, instance->ipi_data,
		   (u64)instance->ipi_phys, (u64)instance->ctrl_phys,
		   (u64)instance->arch.spawn_ctx_phys, instance->instance_pool,
		   instance->pool_size, instance->state);
	mk_instance_put(instance);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(snapshot);

static int __init native_confirm_init(void)
{
	struct dentry *directory;

	if (!enabled || !mk_self || mk_self->id)
		return 0;
	directory = debugfs_create_dir("mk-native-confirm-test", NULL);
	if (IS_ERR(directory))
		return PTR_ERR(directory);
	debugfs_create_u64("fail_cpu", 0600, directory, &fail_cpu);
	debugfs_create_file("snapshot", 0400, directory, NULL, &snapshot_fops);
	return 0;
}
late_initcall(native_confirm_init);
