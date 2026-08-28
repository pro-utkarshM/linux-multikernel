// SPDX-License-Identifier: GPL-2.0-only
#include <linux/cpu.h>
#include <linux/errno.h>
#include <linux/iopoll.h>
#include <linux/ioport.h>
#include <linux/kernel.h>
#include <linux/kexec.h>
#include <linux/libfdt.h>
#include <linux/multikernel.h>
#include <linux/processor.h>
#include <linux/smp.h>

#include <asm/cpu_ops_sbi.h>
#include <asm/sbi.h>

#define MK_HSM_POLL_US		1000
#define MK_HSM_TIMEOUT_US	USEC_PER_SEC

static int mk_riscv_setup_instance(struct mk_instance *instance)
{
	struct mk_riscv_spawn_context *ctx;
	size_t stub_size;
	void *block;

	if (!instance->arch.ctx) {
		stub_size = mk_riscv_entry_stub_end - mk_riscv_entry_stub_start;
		if (WARN_ON_ONCE(!stub_size || stub_size > PAGE_SIZE))
			return -E2BIG;

		block = mk_instance_ctrl_alloc(instance, 2 * PAGE_SIZE,
					       PAGE_SIZE);
		if (!block)
			return -ENOMEM;

		ctx = block;
		memcpy(block + PAGE_SIZE, mk_riscv_entry_stub_start, stub_size);

		instance->arch.ctx = ctx;
		instance->arch.ctx_phys = virt_to_phys(ctx);
		instance->arch.stub = block + PAGE_SIZE;
		instance->arch.stub_phys = instance->arch.ctx_phys + PAGE_SIZE;
	}

	if (!instance->arch.fdt) {
		block = mk_instance_ctrl_alloc(instance, SZ_64K, PAGE_SIZE);
		if (!block)
			return -ENOMEM;

		instance->arch.fdt = block;
		instance->arch.fdt_phys = virt_to_phys(block);
	}

	if (!instance->arch.manifest) {
		block = mk_instance_ctrl_alloc(instance, PAGE_SIZE, PAGE_SIZE);
		if (!block)
			return -ENOMEM;

		instance->arch.manifest = block;
		instance->arch.manifest_phys = virt_to_phys(block);
	}

	return 0;
}

static int mk_riscv_remove_memory_nodes(void *fdt)
{
	for (;;) {
		int node;

		fdt_for_each_subnode(node, fdt, 0) {
			int len;
			const char *type;

			type = fdt_getprop(fdt, node, "device_type", &len);
			if (type && len == sizeof("memory") &&
			    !memcmp(type, "memory", sizeof("memory"))) {
				int ret = fdt_del_node(fdt, node);

				if (ret)
					return ret;
				break;
			}
		}

		if (node == -FDT_ERR_NOTFOUND)
			return 0;
		if (node < 0)
			return node;
	}
}

static int mk_riscv_add_memory_nodes(void *fdt, struct mk_instance *instance)
{
	struct mk_memory_region *region;

	list_for_each_entry(region, &instance->memory_regions, list) {
		u64 start = region->res.start;
		u64 size = resource_size(&region->res);
		char name[32];
		int node, ret;

		snprintf(name, sizeof(name), "memory@%llx", start);
		node = fdt_add_subnode(fdt, 0, name);
		if (node < 0)
			return node;

		ret = fdt_setprop_string(fdt, node, "device_type", "memory");
		if (ret)
			return ret;

		ret = fdt_appendprop_addrrange(fdt, 0, node, "reg",
					       start, size);
		if (ret)
			return ret;
	}

	return 0;
}

static int mk_riscv_limit_cpus(void *fdt, struct mk_instance *instance)
{
	unsigned int assigned = 0;
	int addr_cells, cpus, node;

	cpus = fdt_path_offset(fdt, "/cpus");
	if (cpus < 0)
		return cpus;

	addr_cells = fdt_address_cells(fdt, cpus);
	if (addr_cells < 1 || addr_cells > 2)
		return -FDT_ERR_BADNCELLS;

	fdt_for_each_subnode(node, fdt, cpus) {
		const fdt32_t *reg;
		const char *status, *type;
		u64 hartid = 0;
		int i, len, ret;

		type = fdt_getprop(fdt, node, "device_type", &len);
		if (!type || len != sizeof("cpu") ||
		    memcmp(type, "cpu", sizeof("cpu")))
			continue;

		reg = fdt_getprop(fdt, node, "reg", &len);
		if (!reg || len != addr_cells * sizeof(*reg))
			return -FDT_ERR_BADVALUE;
		for (i = 0; i < addr_cells; i++)
			hartid = (hartid << 32) | fdt32_to_cpu(reg[i]);

		if (!mk_cpu_set_contains(instance->cpus, hartid)) {
			ret = fdt_setprop_string(fdt, node, "status", "disabled");
			if (ret)
				return ret;
			continue;
		}

		status = fdt_getprop(fdt, node, "status", &len);
		if (status &&
		    !((len == sizeof("okay") &&
		       !memcmp(status, "okay", sizeof("okay"))) ||
		      (len == sizeof("ok") &&
		       !memcmp(status, "ok", sizeof("ok")))))
			return -FDT_ERR_BADVALUE;
		assigned++;
	}

	if (node != -FDT_ERR_NOTFOUND)
		return node;
	if (assigned != mk_cpu_set_count(instance->cpus))
		return -FDT_ERR_NOTFOUND;

	return 0;
}

static int mk_riscv_prepare_fdt(struct kimage *image,
				struct mk_instance *instance)
{
	static const char * const handoff_props[] = {
		"multikernel,pool-cpus",
		"multikernel,host-ipi-buffer",
		"multikernel,host-ipi-pages",
		"multikernel,host-ipi-cpu",
		"multikernel,ipi-buffer",
		"multikernel,ipi-pages",
	};
	struct resource ctrl = {
		.start = instance->ctrl_phys,
		.end = instance->ctrl_phys + MK_CTRL_BLOCK_SIZE - 1,
		.flags = IORESOURCE_SYSTEM_RAM,
	};
	struct mk_memory_region *region;
	void *manifest;
	u32 manifest_size;
	bool ctrl_in_grant = false;
	int chosen, i, manifest_chosen, ret;

	image->arch.fdt_addr = 0;
	if (!image->mk_manifest || !instance->arch.manifest ||
	    list_empty(&instance->memory_regions))
		return -EINVAL;

	manifest = phys_to_virt(image->mk_manifest);
	ret = fdt_check_header(manifest);
	if (ret)
		goto out_error;
	manifest_size = fdt_totalsize(manifest);
	if (manifest_size > PAGE_SIZE) {
		ret = -FDT_ERR_NOSPACE;
		goto out_error;
	}

	list_for_each_entry(region, &instance->memory_regions, list) {
		if (resource_contains(&region->res, &ctrl)) {
			ctrl_in_grant = true;
			break;
		}
	}
	if (!ctrl_in_grant)
		return -EINVAL;

	ret = fdt_open_into(image->arch.fdt, instance->arch.fdt, SZ_64K);
	if (ret)
		goto out_error;

	chosen = fdt_path_offset(instance->arch.fdt, "/chosen");
	if (chosen < 0) {
		ret = chosen;
		goto out_error;
	}
	manifest_chosen = fdt_path_offset(manifest, "/chosen");
	if (manifest_chosen < 0) {
		ret = manifest_chosen;
		goto out_error;
	}

	for (i = 0; i < ARRAY_SIZE(handoff_props); i++) {
		const void *prop;
		int len;

		prop = fdt_getprop(manifest, manifest_chosen,
				   handoff_props[i], &len);
		if (!prop)
			continue;
		ret = fdt_setprop(instance->arch.fdt, chosen,
				  handoff_props[i], prop, len);
		if (ret)
			goto out_error;
	}

	ret = fdt_delprop(instance->arch.fdt, chosen,
			  "linux,multikernel-fdt");
	if (ret && ret != -FDT_ERR_NOTFOUND)
		goto out_error;
	ret = fdt_appendprop_addrrange(instance->arch.fdt, 0, chosen,
				       "linux,multikernel-fdt",
				       instance->arch.manifest_phys,
				       PAGE_SIZE);
	if (ret)
		goto out_error;

	ret = mk_riscv_remove_memory_nodes(instance->arch.fdt);
	if (ret)
		goto out_error;

	ret = mk_riscv_add_memory_nodes(instance->arch.fdt, instance);
	if (ret)
		goto out_error;

	ret = mk_riscv_limit_cpus(instance->arch.fdt, instance);
	if (ret)
		goto out_error;

	ret = fdt_add_mem_rsv(instance->arch.fdt, instance->ctrl_phys,
			      MK_CTRL_BLOCK_SIZE);
	if (ret)
		goto out_error;

	ret = fdt_pack(instance->arch.fdt);
	if (ret)
		goto out_error;

	memset(instance->arch.manifest, 0, PAGE_SIZE);
	memcpy(instance->arch.manifest, manifest, manifest_size);
	image->arch.fdt_addr = instance->arch.fdt_phys;
	return 0;

out_error:
	pr_err("mk_spawn: invalid instance DTB: %s\n", fdt_strerror(ret));
	return ret == -FDT_ERR_NOSPACE ? -E2BIG : -EINVAL;
}

static int mk_riscv_hart_stopped(unsigned long hartid)
{
	int state, ret;

	state = sbi_hsm_hart_get_status(hartid);
	if (state == SBI_HSM_STATE_STARTED ||
	    state == SBI_HSM_STATE_START_PENDING ||
	    state == SBI_HSM_STATE_STOP_PENDING) {
		ret = read_poll_timeout(sbi_hsm_hart_get_status, state,
					state != SBI_HSM_STATE_STARTED &&
					state != SBI_HSM_STATE_START_PENDING &&
					state != SBI_HSM_STATE_STOP_PENDING,
					MK_HSM_POLL_US, MK_HSM_TIMEOUT_US,
					false, hartid);
		if (ret) {
			pr_err("mk_spawn: hart %lu did not stop within %ld us\n",
			       hartid, MK_HSM_TIMEOUT_US);
			return -EBUSY;
		}
	}

	if (state < 0) {
		if (state == -EPERM)
			pr_err("mk_spawn: SBI domain denied HART_STATUS for hart %lu\n",
			       hartid);
		else
			pr_err("mk_spawn: failed to query hart %lu status: %d\n",
			       hartid, state);
		return state;
	}
	if (state != SBI_HSM_STATE_STOPPED) {
		pr_err("mk_spawn: hart %lu is not stopped (state %d)\n",
		       hartid, state);
		return -EBUSY;
	}

	return 0;
}

static int mk_riscv_prime_icache(unsigned long hartid)
{
	int ret;

	ret = mk_riscv_hart_stopped(hartid);
	if (ret)
		return ret;

	ret = sbi_hsm_hart_start(hartid,
				 __pa_symbol(mk_riscv_entry_fence_stop), 0);
	if (ret) {
		pr_err("mk_spawn: failed to prime hart %lu I-cache: %d\n",
		       hartid, ret);
		return ret;
	}

	return mk_riscv_hart_stopped(hartid);
}

void mk_arch_send_ipi(mk_phys_cpu_t phys_cpu)
{
	struct sbiret ret;

	/* The host doorbell hart is intentionally absent from a spawn's CPU map. */
	ret = sbi_ecall(SBI_EXT_IPI, SBI_EXT_IPI_SEND_IPI,
			1UL, phys_cpu, 0, 0, 0, 0);
	if (ret.error)
		pr_err("Multikernel: failed to send IPI to hart %llu: %d\n",
		       phys_cpu, sbi_err_map_linux_errno(ret.error));
}

void mk_arch_register_cpu(mk_phys_cpu_t phys_id)
{
	/* RISC-V CPU topology already records possible harts. */
}

void __noreturn mk_enter_pool_state(void *info)
{
	int ret;

	local_irq_disable();
	set_cpu_online(smp_processor_id(), false);
	/* Publish the offline state before firmware stops this hart. */
	smp_mb();

	ret = sbi_hsm_hart_stop();
	pr_emerg("Multikernel: HART_STOP returned on CPU %u: %d\n",
		 smp_processor_id(), ret);
	for (;;)
		wait_for_interrupt();
}

int mk_arch_register_force_stop(void)
{
	return -EOPNOTSUPP;
}

void mk_force_stop_cpu(mk_phys_cpu_t phys_cpu)
{
	pr_warn_once("RISC-V multikernel force-stop is not implemented\n");
}

int mk_arch_spawn_instance(struct kimage *image, struct mk_instance *instance,
			   int cpu)
{
	unsigned long hartid = arch_cpu_physical_id(cpu);
	mk_phys_cpu_t phys_cpu;
	unsigned int i;
	int ret;

	if (hartid == INVALID_HARTID || !image->start || !image->arch.fdt)
		return -EINVAL;

	ret = mk_riscv_setup_instance(instance);
	if (ret)
		return ret;

	ret = mk_manifest_set_entry_stub(image, instance->arch.stub_phys);
	if (ret)
		return ret;

	ret = mk_riscv_prepare_fdt(image, instance);
	if (ret) {
		pr_err("mk_spawn: failed to build instance DTB: %d\n", ret);
		return ret;
	}

	WRITE_ONCE(instance->arch.ctx->image_entry, image->start);
	/* Publish all Image, DTB, stub and context stores before starting it. */
	smp_mb();
	mk_cpu_set_for_each(i, phys_cpu, instance->cpus) {
		ret = mk_riscv_prime_icache(phys_cpu);
		if (ret)
			return ret;
	}

	ret = sbi_hsm_hart_start(hartid, instance->arch.stub_phys,
				 image->arch.fdt_addr);
	if (ret == -EPERM)
		pr_err("mk_spawn: SBI domain denied HART_START for hart %lu\n",
		       hartid);
	else if (ret == -EINVAL)
		pr_err("mk_spawn: invalid HART_START parameters for hart %lu\n",
		       hartid);
	else if (ret)
		pr_err("mk_spawn: failed to start hart %lu: %d\n", hartid, ret);

	return ret;
}

int mk_arch_release_instance(struct mk_instance *instance)
{
	int ret;

	ret = mk_instance_confirm_parked(instance);
	if (ret)
		return ret;

	instance->arch.ctx = NULL;
	instance->arch.ctx_phys = 0;
	instance->arch.stub = NULL;
	instance->arch.stub_phys = 0;
	instance->arch.fdt = NULL;
	instance->arch.fdt_phys = 0;
	instance->arch.manifest = NULL;
	instance->arch.manifest_phys = 0;
	return 0;
}

int mk_arch_confirm_parked(struct mk_instance *instance,
			   mk_phys_cpu_t phys_cpu)
{
	return mk_riscv_hart_stopped(phys_cpu);
}

int mk_repark_instance_to_host(struct mk_instance *instance)
{
	return 0;
}

int mk_repark_cpu_to_instance(struct mk_instance *instance,
			      mk_phys_cpu_t phys_cpu)
{
	if (!instance->arch.stub)
		return -EINVAL;

	return mk_riscv_prime_icache(phys_cpu);
}

int mk_repark_cpu_to_host(struct mk_instance *instance,
			  mk_phys_cpu_t phys_cpu)
{
	return 0;
}
