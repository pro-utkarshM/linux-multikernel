/* SPDX-License-Identifier: GPL-2.0-only */
/* Test branch only: default-off, host-only, target instance 1. */
static bool mk_test_resource_trace;
static bool mk_test_resource_target(struct mk_instance *instance)
{
	return mk_test_resource_trace && mk_self && mk_self->id == 0 &&
		instance && instance->id == 1;
}
static void mk_test_snapshot(struct mk_instance *instance, const char *phase)
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
