// SPDX-License-Identifier: GPL-2.0-only
/* Real sequential tree writer: boot hook must not affect control readback. */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <libfdt.h>

/* Modeled pool alignment; this fixture exercises child boot emission. */
#define MHP_SUBSECTIONS_ALIGN (2ULL << 20)

struct mk_instance { const char *name; int id; void *cpus, *host_tree; };
static struct mk_instance self, target = { .name = "child", .id = 1 };
static struct mk_instance *mk_self = &self;
static struct { void *cpus; } *mk_pool;
static int calls, error;

int mk_arch_boot_nodes(void *fdt, struct mk_instance *instance)
{
	int ret;

	assert(instance == &target);
	calls++;
	if (error)
		return error;
	ret = fdt_begin_node(fdt, "memory@90000000");
	if (!ret)
		ret = fdt_property_string(fdt, "device_type", "memory");
	return ret ? ret : fdt_end_node(fdt);
}

static int mk_dt_emit_pool_members(void *fdt) { return 0; }
static int mk_dt_emit_cpu_prop(void *fdt, const char *p, void *cpus) { return 0; }
static int mk_dt_emit_instance_memory(struct mk_instance *i, void *fdt) { return 0; }
static int mk_dt_emit_pool_chunk(void *p, void *fdt) { return 0; }
static int mk_pool_for_each_chunk(int (*cb)(void *, void *), void *data) { return 0; }
static int mk_dt_emit_devices(struct mk_instance *i, void *fdt) { return 0; }
static int mk_dt_emit_aliases(struct mk_instance *i, void *fdt) { return 0; }
static int mk_dt_emit_host_bridges(struct mk_instance *i, void *fdt) { return 0; }
static int mk_dt_emit_own_devices(void *fdt) { return 0; }
static int mk_dt_emit_requested_chosen(void *fdt, void *data) { return 0; }
static unsigned long mk_manifest_phys(void) { return 0; }

#include "tree.h"

int main(void)
{
	char fdt[8192];

	assert(!mk_dt_emit_boot_tree(&target, fdt, sizeof(fdt), NULL, NULL));
	assert(calls == 1);
	assert(fdt_path_offset(fdt, "/memory@90000000") >= 0);
	assert(!mk_dt_emit_instance(&target, fdt, sizeof(fdt)));
	assert(calls == 1 && fdt_path_offset(fdt, "/memory@90000000") < 0);
	error = -FDT_ERR_NOSPACE;
	assert(mk_dt_emit_boot_tree(&target, fdt, sizeof(fdt), NULL, NULL) == error);
	assert(calls == 2);
	puts("PASS: boot-only node emission and error propagation; control tree unchanged");
	return 0;
}
