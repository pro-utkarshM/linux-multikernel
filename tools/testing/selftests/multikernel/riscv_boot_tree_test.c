// SPDX-License-Identifier: GPL-2.0-only
/* Real boot-node writer/libfdt; controlled Linux topology boundaries. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <libfdt.h>

#define __weak
#define __init
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint64_t mk_phys_cpu_t;
#define PAGE_SHIFT 12
#define MK_MANIFEST_SIZE (256 * 1024)
#define MK_CTRL_BLOCK_SIZE (64 * 1024 + 8192)
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define for_each_possible_cpu(cpu) for ((cpu) = 0; (cpu) < 2; (cpu)++)
#define list_for_each_entry(p, h, member) for ((p) = (h)->first; (p); (p) = (p)->next)
#define resource_size(r) ((r)->end - (r)->start + 1)
#define list_empty(h) (!(h)->first)
#define mk_cpu_set_empty(s) (!(s) || !(s)->nr)
#define mk_cpu_set_for_each(i, id, set) \
	for ((i) = 0; (i) < (set)->nr && (((id) = (set)->ids[i]), true); (i)++)
struct resource { u64 start, end; };
struct mk_memory_region { struct resource res; struct mk_memory_region *next; };
struct mk_cpu_set { unsigned int nr; u64 ids[2]; };
struct mk_instance {
	struct { struct mk_memory_region *first; } memory_regions;
	struct mk_cpu_set *cpus;
	u64 ctrl_phys, manifest_phys, ipi_phys;
	u32 ipi_pages;
	int pci_device_count, platform_device_count;
};
struct device_node { int node; };
static char host_fdt[8192];
static struct device_node nodes[8192];
static struct mk_instance parent, *mk_self = &parent;
static bool spawned;
static unsigned long cpuid_to_hartid_map(int cpu) { return cpu ? 7 : 65537; }
static int arch_cpu_from_physical_id(u64 id) { return id == 65537 ? 0 : id == 7 ? 1 : -1; }
static bool mk_cpu_set_contains(struct mk_cpu_set *s, u64 id)
{
	unsigned int i;
	for (i = 0; i < s->nr; i++)
		if (s->ids[i] == id)
			return true;
	return false;
}
static bool mk_spawned(void) { return spawned; }
static struct device_node *of_find_node_by_path(const char *path)
{
	int n = fdt_path_offset(host_fdt, path);
	if (n < 0)
		return NULL;
	nodes[n].node = n;
	return &nodes[n];
}
static struct device_node *of_get_cpu_node(int cpu, void *unused)
{
	return of_find_node_by_path(cpu ? "/cpus/cpu@7" : "/cpus/cpu@10001");
}
static const void *of_get_property(struct device_node *n, const char *p, int *len)
{
	return fdt_getprop(host_fdt, n->node, p, len);
}
static int of_property_read_u32(struct device_node *n, const char *p, u32 *v)
{
	const fdt32_t *a = of_get_property(n, p, NULL);
	if (!a)
		return -EINVAL;
	*v = fdt32_ld(a);
	return 0;
}
static int of_property_count_u64_elems(struct device_node *n, const char *p)
{
	int len;
	if (!of_get_property(n, p, &len) || len % 8)
		return -EINVAL;
	return len / 8;
}
static int of_property_read_u64_index(struct device_node *n, const char *p, int i, u64 *v)
{
	const fdt64_t *a = of_get_property(n, p, NULL);
	*v = fdt64_ld(a + i);
	return 0;
}
static void of_node_put(struct device_node *n) { }

#include "boot.h"

static void make_host(void)
{
	int i;
	fdt64_t grant = cpu_to_fdt64(65537);
	assert(!fdt_create(host_fdt, sizeof(host_fdt)));
	assert(!fdt_finish_reservemap(host_fdt) && !fdt_begin_node(host_fdt, ""));
	assert(!fdt_begin_node(host_fdt, "resources"));
	assert(!fdt_property(host_fdt, "cpus", &grant, sizeof(grant)));
	assert(!fdt_end_node(host_fdt));
	assert(!fdt_begin_node(host_fdt, "cpus"));
	assert(!fdt_property_u32(host_fdt, "timebase-frequency", 10000000));
	for (i = 0; i < 2; i++) {
		assert(!fdt_begin_node(host_fdt, i ? "cpu@7" : "cpu@10001"));
		assert(!fdt_property_string(host_fdt, "device_type", "cpu"));
		assert(!fdt_property_string(host_fdt, "compatible", "riscv"));
		assert(!fdt_property_string(host_fdt, "riscv,isa", "rv64imafdc_zicsr_zifencei"));
		assert(!fdt_property_string(host_fdt, "mmu-type", "riscv,sv39"));
		assert(!fdt_property_u32(host_fdt, "riscv,cbom-block-size", 64));
		assert(!fdt_property_u32(host_fdt, "riscv,cboz-block-size", 64));
		assert(!fdt_property_u32(host_fdt, "riscv,cbop-block-size", 64));
		assert(!fdt_end_node(host_fdt));
	}
	assert(!fdt_end_node(host_fdt) && !fdt_end_node(host_fdt) && !fdt_finish(host_fdt));
}

int main(void)
{
	struct mk_memory_region second = { .res = { 0xa0000000, 0xa3ffffff } };
	struct mk_memory_region first = { .res = { 0x90000000, 0x93ffffff }, .next = &second };
	struct mk_cpu_set cpus = { .nr = 1, .ids = { 65537 } };
	struct mk_instance instance = {
		.memory_regions.first = &first, .cpus = &cpus,
		.ctrl_phys = 0x92000000, .manifest_phys = 0x91000000,
		.ipi_phys = 0x91800000, .ipi_pages = 65,
	};
	char fdt[16384];
	const fdt64_t *reg;
	int len, n;

	parent.ipi_phys = 0x88000000;
	parent.ipi_pages = 65;
	make_host();
	assert(mk_riscv_cpu_assigned(0) && mk_riscv_cpu_assigned(1));
	spawned = true;
	assert(mk_riscv_cpu_assigned(0) && !mk_riscv_cpu_assigned(1));
	assert(!fdt_create(fdt, sizeof(fdt)) && !fdt_finish_reservemap(fdt));
	assert(!fdt_begin_node(fdt, ""));
	assert(!mk_arch_boot_nodes(fdt, &instance));
	assert(!fdt_end_node(fdt) && !fdt_finish(fdt));
	n = fdt_path_offset(fdt, "/memory@90000000");
	assert(n >= 0);
	reg = fdt_getprop(fdt, n, "reg", &len);
	assert(reg && len == 16 && fdt64_ld(reg) == 0x90000000 && fdt64_ld(reg + 1) == 0x4000000);
	assert(fdt_path_offset(fdt, "/memory@a0000000") >= 0);
	assert(fdt_path_offset(fdt, "/cpus/cpu@10001/interrupt-controller") >= 0);
	assert(fdt_path_offset(fdt, "/cpus/cpu@7/interrupt-controller") >= 0);
	n = fdt_path_offset(fdt, "/cpus/cpu@7");
	assert(fdt_getprop(fdt, n, "riscv,cbom-block-size", &len) && len == 4);
	assert(fdt_getprop(fdt, n, "riscv,cboz-block-size", &len) && len == 4);
	assert(fdt_getprop(fdt, n, "riscv,cbop-block-size", &len) && len == 4);
	assert(fdt_path_offset(fdt, "/reserved-memory/control@92000000") >= 0);
	instance.memory_regions.first = NULL;
	assert(!fdt_create(fdt, sizeof(fdt)) && !fdt_finish_reservemap(fdt));
	assert(!fdt_begin_node(fdt, ""));
	assert(mk_arch_boot_nodes(fdt, &instance) == -EINVAL);
	puts("PASS: sparse hart topology, disjoint memory and protected boot ranges");
	return 0;
}
