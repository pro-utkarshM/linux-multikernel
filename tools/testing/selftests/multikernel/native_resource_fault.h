/* SPDX-License-Identifier: GPL-2.0-only */
/* Test branch only: default-off, host-only, target instance 1. */
#include "native_resource_trace.h"

#ifdef CONFIG_RISCV
static u64 mk_test_hsm_sample;
static void mk_test_hart_snapshot(struct mk_instance *instance,
				  mk_phys_cpu_t hart, u64 sample)
{
	struct sbiret ret;

	/* Observe once: never poll, start, stop or retire tracking here. */
	ret = sbi_ecall(SBI_EXT_HSM, SBI_EXT_HSM_HART_STATUS, hart,
			0, 0, 0, 0, 0);
	pr_info("MK_TEST_HSM id=%d phase=exec-rejected sample=%llu hart=%llu state=%ld error=%ld\n",
		instance->id, sample, hart, ret.error ? -1L : ret.value, ret.error);
}
#endif

static bool mk_test_resource_trace;
static bool mk_test_resource_target(struct mk_instance *instance)
{
	return mk_test_resource_trace && mk_self && mk_self->id == 0 &&
		instance && instance->id == 1;
}

void mk_test_snapshot(struct mk_instance *instance, const char *phase)
{
	if (!mk_test_resource_target(instance))
		return;
	lockdep_assert_held(&mk_overlay_mutex);
	pr_info("MK_TEST_RESOURCE id=%d phase=%s state=%s image=%llx ctrl=%llx manifest=%llx ring=%llx pool=%llx size=%zu owned=%u tracked=%u ring_size=%u manifest_size=%lu\n",
		instance->id, phase, mk_state_to_string(instance->state),
		(unsigned long long)(unsigned long)instance->kimage,
		(unsigned long long)instance->ctrl_phys,
		(unsigned long long)instance->manifest_phys,
		(unsigned long long)instance->ipi_phys,
		(unsigned long long)(unsigned long)instance->instance_pool,
		instance->pool_size,
		instance->cpus ? mk_cpu_set_count(instance->cpus) : 0,
		instance->cpus_on_slot ? mk_cpu_set_count(instance->cpus_on_slot) : 0,
		instance->ipi_pages << PAGE_SHIFT, (unsigned long)MK_MANIFEST_SIZE);
#ifdef CONFIG_RISCV
	if (!strcmp(phase, "exec-rejected")) {
		mk_phys_cpu_t hart;
		unsigned int i;
		u64 sample = ++mk_test_hsm_sample;

		/* The resource lock keeps the assigned/tracked union stable. */
		mk_cpu_set_for_each(i, hart, instance->cpus)
			mk_test_hart_snapshot(instance, hart, sample);
		mk_cpu_set_for_each(i, hart, instance->cpus_on_slot)
			if (!mk_cpu_set_contains(instance->cpus, hart))
				mk_test_hart_snapshot(instance, hart, sample);
	}
#endif
}
static void mk_test_free(struct mk_instance *instance, const char *kind,
			 phys_addr_t address, size_t size)
{
	if (!mk_test_resource_target(instance))
		return;
	pr_info("MK_TEST_FREE id=%d kind=%s phys=%llx size=%zu pool=%llx\n",
		instance->id, kind, (unsigned long long)address, size,
		(unsigned long long)(unsigned long)instance->instance_pool);
}
