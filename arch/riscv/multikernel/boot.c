// SPDX-License-Identifier: GPL-2.0-only
/* Test-only #27 adapter: device-less QEMU virt boot trees, not DT filtering. */
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/libfdt.h>
#include <linux/multikernel.h>
#include <linux/of.h>
#include <linux/smp.h>

/* Only initial present membership; hot-add updates ownership through workers. */
bool mk_riscv_cpu_assigned(unsigned int cpu)
{
	struct device_node *np;
	u64 hart;
	int i, count;
	bool assigned = false;

	if (!mk_spawned())
		return true;
	np = of_find_node_by_path("/resources");
	if (!np)
		return false;
	count = of_property_count_u64_elems(np, "cpus");
	for (i = 0; i < count; i++) {
		if (of_property_read_u64_index(np, "cpus", i, &hart))
			break;
		if (hart == cpuid_to_hartid_map(cpu)) {
			assigned = true;
			break;
		}
	}
	of_node_put(np);
	return assigned;
}

static int mk_boot_range(void *fdt, const char *kind, u64 start, u64 size,
			 bool reserved)
{
	fdt64_t reg[] = { cpu_to_fdt64(start), cpu_to_fdt64(size) };
	char name[64];
	int ret;

	if (!size || start > (u64)-1 - size)
		return -EINVAL;
	snprintf(name, sizeof(name), "%s@%llx", kind, (unsigned long long)start);
	ret = fdt_begin_node(fdt, name);
	if (!ret && !reserved)
		ret = fdt_property_string(fdt, "device_type", "memory");
	if (!ret)
		ret = fdt_property(fdt, "reg", reg, sizeof(reg));
	if (!ret && reserved)
		ret = fdt_property(fdt, "no-map", NULL, 0);
	return ret ? ret : fdt_end_node(fdt);
}

static int mk_boot_cpu_property(void *fdt, struct device_node *np,
				const char *name, bool required)
{
	const void *value;
	int len;

	value = of_get_property(np, name, &len);
	if (!value)
		return required ? -EINVAL : 0;
	if (len <= 0)
		return -EINVAL;
	return fdt_property(fdt, name, value, len);
}

static int mk_boot_cpu(void *fdt, unsigned int cpu)
{
	struct device_node *np = of_get_cpu_node(cpu, NULL);
	u64 hart = cpuid_to_hartid_map(cpu);
	char name[48];
	int ret;

	if (!np)
		return -ENODEV;
	snprintf(name, sizeof(name), "cpu@%llx", (unsigned long long)hart);
	ret = fdt_begin_node(fdt, name);
	if (!ret)
		ret = fdt_property_u64(fdt, "reg", hart);
	if (!ret)
		ret = fdt_property_string(fdt, "status", "okay");
	if (!ret)
		ret = mk_boot_cpu_property(fdt, np, "device_type", true);
	if (!ret)
		ret = mk_boot_cpu_property(fdt, np, "compatible", true);
	if (!ret)
		ret = mk_boot_cpu_property(fdt, np, "mmu-type", true);
	if (!ret)
		ret = mk_boot_cpu_property(fdt, np, "riscv,isa", false);
	if (!ret)
		ret = mk_boot_cpu_property(fdt, np, "riscv,isa-base",
					    !of_get_property(np, "riscv,isa", NULL));
	if (!ret)
		ret = mk_boot_cpu_property(fdt, np, "riscv,isa-extensions",
					    !of_get_property(np, "riscv,isa", NULL));
	of_node_put(np);
	if (!ret)
		ret = fdt_begin_node(fdt, "interrupt-controller");
	if (!ret)
		ret = fdt_property_u32(fdt, "#interrupt-cells", 1);
	if (!ret)
		ret = fdt_property(fdt, "interrupt-controller", NULL, 0);
	if (!ret)
		ret = fdt_property_string(fdt, "compatible", "riscv,cpu-intc");
	if (!ret)
		ret = fdt_property_u32(fdt, "phandle", 0x1000 + cpu);
	if (!ret)
		ret = fdt_end_node(fdt);
	return ret ? ret : fdt_end_node(fdt);
}

int mk_arch_boot_nodes(void *fdt, struct mk_instance *instance)
{
	struct mk_memory_region *region;
	struct device_node *np;
	mk_phys_cpu_t hart;
	unsigned int i, cpu;
	u32 timebase;
	int ret;

	/* No borrowed platform/PCI devices are described by this test adapter. */
	if (instance->pci_device_count || instance->platform_device_count)
		return -EOPNOTSUPP;
	if (list_empty(&instance->memory_regions) || mk_cpu_set_empty(instance->cpus) ||
	    !instance->ctrl_phys || !instance->manifest_phys ||
	    !instance->ipi_phys || !instance->ipi_pages)
		return -EINVAL;
	mk_cpu_set_for_each(i, hart, instance->cpus)
		if (arch_cpu_from_physical_id(hart) < 0)
			return -EINVAL;
	list_for_each_entry(region, &instance->memory_regions, list) {
		if (region->res.end < region->res.start)
			return -EINVAL;
		ret = mk_boot_range(fdt, "memory", region->res.start,
				    resource_size(&region->res), false);
		if (ret)
			return ret;
	}

	np = of_find_node_by_path("/cpus");
	if (!np)
		return -ENODEV;
	ret = of_property_read_u32(np, "timebase-frequency", &timebase);
	of_node_put(np);
	if (ret || !timebase)
		return -EINVAL;
	ret = fdt_begin_node(fdt, "cpus");
	if (!ret)
		ret = fdt_property_u32(fdt, "#address-cells", 2);
	if (!ret)
		ret = fdt_property_u32(fdt, "#size-cells", 0);
	if (!ret)
		ret = fdt_property_u32(fdt, "timebase-frequency", timebase);
	for_each_possible_cpu(cpu) {
		if (ret)
			return ret;
		/* Possible is topology, not ownership; the early present filter wins. */
		ret = mk_boot_cpu(fdt, cpu);
	}
	if (!ret)
		ret = fdt_end_node(fdt);
	if (!ret)
		ret = fdt_begin_node(fdt, "reserved-memory");
	if (!ret)
		ret = fdt_property_u32(fdt, "#address-cells", 2);
	if (!ret)
		ret = fdt_property_u32(fdt, "#size-cells", 2);
	if (!ret)
		ret = fdt_property(fdt, "ranges", NULL, 0);
	if (!ret)
		ret = mk_boot_range(fdt, "control", instance->ctrl_phys,
				    MK_CTRL_BLOCK_SIZE, true);
	if (!ret)
		ret = mk_boot_range(fdt, "manifest", instance->manifest_phys,
				    MK_MANIFEST_SIZE, true);
	if (!ret)
		ret = mk_boot_range(fdt, "inbox", instance->ipi_phys,
				    (u64)instance->ipi_pages << PAGE_SHIFT, true);
	if (!ret && mk_self && mk_self->ipi_pages)
		ret = mk_boot_range(fdt, "parent-inbox", mk_self->ipi_phys,
				    (u64)mk_self->ipi_pages << PAGE_SHIFT, true);
	return ret ? ret : fdt_end_node(fdt);
}
