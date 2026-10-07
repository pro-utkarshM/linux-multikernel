// SPDX-License-Identifier: GPL-2.0-only
/* Test-only VM instrumentation. Never include in the production series. */
#include <linux/debugfs.h>
#include <linux/atomic.h>
#include <linux/dmi.h>
#include <linux/init.h>
#include <linux/ktime.h>
#include <linux/limits.h>
#include <linux/module.h>
#include <linux/multikernel.h>
#include <linux/mutex.h>
#include <linux/seq_file.h>
#include <linux/string.h>

static bool enabled;
static bool safe_vm;
static u64 fail_cpu = U64_MAX;
static atomic64_t failure_count = ATOMIC64_INIT(0);
static bool probe_used;
static u64 probe_cpu = U64_MAX;
static u64 probe_elapsed_us;
static int probe_result, probe_retry, probe_repark;

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
	if (!enabled || !safe_vm || !mk_self || mk_self->id ||
	    phys_cpu != READ_ONCE(fail_cpu))
		return false;
	pr_info("MK_X86_TEST_CONFIRM_FAIL phys=%llu\n", phys_cpu);
	atomic64_inc(&failure_count);
	return true;
}

static int failures_get(void *unused, u64 *value)
{
	*value = atomic64_read(&failure_count);
	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(failures_fops, failures_get, NULL, "%llu\n");

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

/* One disposable VM only: no slot writes, injection, recovery or force-stop. */
static int mailbox_probe_set(void *unused, u64 phys_cpu)
{
	struct mk_instance *instance;
	ktime_t start;
	int ret = -EINVAL;

	if (!enabled || !safe_vm || !mk_self || mk_self->id)
		return -EPERM;
	if (phys_cpu > U32_MAX)
		return -EINVAL;
	guard(mutex)(&mk_overlay_mutex);
	if (probe_used || READ_ONCE(fail_cpu) != U64_MAX ||
	    atomic64_read(&failure_count))
		return -EBUSY;
	instance = mk_instance_find(1);
	if (!instance)
		return -ENOENT;
	if (instance->state != MK_STATE_ACTIVE ||
	    !mk_cpu_set_contains(instance->cpus, phys_cpu) ||
	    !mk_cpu_set_contains(instance->cpus_on_slot, phys_cpu) ||
	    !instance->arch.spawn_ctx || !mk_pool || !mk_pool->arch.slot)
		goto out;
	if (READ_ONCE(instance->arch.spawn_ctx->ready) != MK_SLOT_IDLE ||
	    READ_ONCE(mk_pool->arch.slot->ready) != MK_SLOT_IDLE) {
		ret = -EBUSY;
		goto out;
	}
	probe_used = true;
	probe_cpu = phys_cpu;
	start = ktime_get();
	probe_result = mk_arch_confirm_parked(instance, phys_cpu);
	probe_elapsed_us = ktime_us_delta(ktime_get(), start);
	if (probe_result == -ETIMEDOUT) {
		probe_retry = mk_arch_confirm_parked(instance, phys_cpu);
		probe_repark = mk_repark_instance_to_host(instance);
	}
	/* Expose native results separately from debugfs write admission. */
	ret = 0;
out:
	mk_instance_put(instance);
	return ret;
}
DEFINE_DEBUGFS_ATTRIBUTE(mailbox_probe_fops, NULL, mailbox_probe_set, "%llu\n");

static int mailbox_show(struct seq_file *seq, void *unused)
{
	struct mk_instance *instance;
	struct mk_spawn_context *ctx;

	guard(mutex)(&mk_overlay_mutex);
	instance = mk_instance_find(1);
	if (!instance)
		return -ENOENT;
	ctx = instance->arch.spawn_ctx;
	if (!ctx || !mk_pool || !mk_pool->arch.slot) {
		mk_instance_put(instance);
		return -EINVAL;
	}
	seq_printf(seq,
		   "{\"used\":%u,\"cpu\":%llu,\"result\":%d,\"retry\":%d,"
		   "\"repark\":%d,\"elapsed_us\":%llu,\"selected_state\":%u,"
		   "\"pool_state\":%u,\"tracked\":%u,\"tracked_count\":%u,"
		   "\"instance_slot\":\"%llx\",\"instance_park\":\"%llx\","
		   "\"pool_slot\":\"%llx\",\"pool_park\":\"%llx\",\"pool_cr3\":\"%llx\"}\n",
		   probe_used, probe_cpu, probe_result, probe_retry, probe_repark,
		   probe_elapsed_us, READ_ONCE(ctx->ready),
		   READ_ONCE(mk_pool->arch.slot->ready),
		   mk_cpu_set_contains(instance->cpus_on_slot, probe_cpu),
		   mk_cpu_set_count(instance->cpus_on_slot),
		   (u64)instance->arch.spawn_ctx_phys, (u64)ctx->park_phys,
		   (u64)mk_pool->arch.slot_phys, (u64)mk_pool->arch.park_phys,
		   (u64)mk_pool->arch.cr3);
	mk_instance_put(instance);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(mailbox);

static int __init native_confirm_init(void)
{
	struct dentry *directory;

	if (!enabled || !mk_self || mk_self->id)
		return 0;
	if (!dmi_match(DMI_SYS_VENDOR, "QEMU") ||
	    !dmi_match(DMI_PRODUCT_NAME, "Standard PC (Q35 + ICH9, 2009)")) {
		pr_warn("MK_X86_TEST_CONFIRM_REFUSED: not the QEMU q35 lane\n");
		return 0;
	}
	safe_vm = true;
	directory = debugfs_create_dir("mk-native-confirm-test", NULL);
	if (IS_ERR(directory))
		return PTR_ERR(directory);
	debugfs_create_u64("fail_cpu", 0600, directory, &fail_cpu);
	debugfs_create_file("failures", 0400, directory, NULL, &failures_fops);
	debugfs_create_file("snapshot", 0400, directory, NULL, &snapshot_fops);
	debugfs_create_file("probe", 0200, directory, NULL, &mailbox_probe_fops);
	debugfs_create_file("mailbox", 0400, directory, NULL, &mailbox_fops);
	return 0;
}
late_initcall(native_confirm_init);
