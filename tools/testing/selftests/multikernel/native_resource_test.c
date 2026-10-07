// SPDX-License-Identifier: GPL-2.0-only
/* Real free-site definitions; allocator/printing substituted at boundaries. */
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
typedef unsigned long phys_addr_t;
typedef unsigned long long u64;
#include "resource-types.h"
#define MK_MANIFEST_SIZE 4096
#define PAGE_SHIFT 12
struct mk_shared_data { char data[8192]; };
struct mk_instance {
	int id, state;
	void *instance_pool, *kimage, *ctrl_va, *ipi_data;
	unsigned long ctrl_phys, manifest_phys, ipi_phys;
	size_t pool_size;
	unsigned int ipi_pages;
	struct mk_cpu_set *cpus, *cpus_on_slot;
};
static struct { int id; } host = { 0 }, *mk_self = &host;
static bool mk_overlay_mutex = true;
#define lockdep_assert_held(lock) assert(*(lock))
static unsigned int frees, markers;
static char output[2048];
static void print_marker(const char *format, ...);
#define pr_info(...) print_marker(__VA_ARGS__)
static const char *mk_state_to_string(int state) { (void)state; return "failed"; }
bool mk_cpu_set_contains(const struct mk_cpu_set *set, mk_phys_cpu_t id)
{
	unsigned int i;
	mk_phys_cpu_t entry;

	mk_cpu_set_for_each(i, entry, set)
		if (entry == id)
			return true;
	return false;
}
#define SBI_EXT_HSM 0x48534d
#define SBI_EXT_HSM_HART_STATUS 2
struct sbiret { long error, value; };
static long firmware_error, firmware_state = 1;
static mk_phys_cpu_t queried[32];
static unsigned int queries;
static char hsm_output[4096];
static struct sbiret sbi_ecall(unsigned long ext, unsigned long fid,
			     unsigned long hart, unsigned long a1,
			     unsigned long a2, unsigned long a3,
			     unsigned long a4, unsigned long a5)
{
	assert(mk_overlay_mutex);
	assert(ext == SBI_EXT_HSM && fid == SBI_EXT_HSM_HART_STATUS);
	assert(!a1 && !a2 && !a3 && !a4 && !a5);
	assert(queries < sizeof(queried) / sizeof(*queried));
	queried[queries++] = hart;
	return (struct sbiret) { firmware_error, firmware_state };
}
static unsigned int get_order(size_t size) { return size > 4096 ? 1 : 0; }
static void *phys_to_page(phys_addr_t addr) { return (void *)addr; }
static phys_addr_t virt_to_phys(void *addr) { return (uintptr_t)addr; }
static void __free_pages(void *page, unsigned int order)
{ (void)page; (void)order; frees++; }
static void multikernel_instance_free(void *pool, phys_addr_t addr, size_t size)
{ assert(pool && addr && size); frees++; }
#if __has_include("native_resource_fault.h")
#include "native_resource_fault.h"
#else
static bool mk_test_resource_trace;
#endif
#include "resource-sites.h"
#include <stdarg.h>
static void print_marker(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	vsnprintf(output, sizeof(output), format, args);
	va_end(args);
	if (strstr(output, "MK_TEST_HSM ")) {
		assert(strlen(hsm_output) + strlen(output) < sizeof(hsm_output));
		strcat(hsm_output, output);
	}
	markers++;
}

static void test_rejected_snapshots(struct mk_instance *instance)
{
	mk_phys_cpu_t assigned[] = { 65537, 7 };
	mk_phys_cpu_t tracked[] = { 7, 0x123456789abcdef0ULL };
	struct mk_cpu_set owned = { .nr = 2, .cap = 2, .ids = assigned };
	struct mk_cpu_set orphan = { .nr = 2, .cap = 2, .ids = tracked };
	struct mk_instance before;
	unsigned int old_markers = markers;

	instance->cpus = &owned;
	instance->cpus_on_slot = &orphan;
	before = *instance;
	/* Not host, not target, and default-off must do no firmware work. */
	mk_test_snapshot(instance, "exec-rejected");
	host.id = 0;
	instance->id = 2;
	mk_test_snapshot(instance, "exec-rejected");
	instance->id = 1;
	mk_test_resource_trace = false;
	mk_test_snapshot(instance, "exec-rejected");
	assert(!queries && markers == old_markers);
	mk_test_resource_trace = true;
	mk_test_snapshot(instance, "state");
	assert(!queries);
	mk_test_snapshot(instance, "exec-rejected");
	assert(queries == 3);
	assert(queried[0] == assigned[0] && queried[1] == assigned[1]);
	assert(queried[2] == tracked[1]);
	assert(strstr(hsm_output, "id=1 phase=exec-rejected sample=1 hart=65537 state=1 error=0"));
	assert(strstr(hsm_output, "sample=1 hart=1311768467463790320 state=1 error=0"));
	assert(!memcmp(instance, &before, sizeof(before)));
	assert(owned.nr == 2 && orphan.nr == 2 && tracked[0] == 7);
	assert(assigned[0] == 65537 && assigned[1] == 7 && tracked[1] == 0x123456789abcdef0ULL);
	/* Failed status cannot masquerade as STOPPED via an undefined value. */
	firmware_error = -4;
	hsm_output[0] = '\0';
	mk_test_snapshot(instance, "exec-rejected");
	assert(queries == 6 && strstr(hsm_output, "sample=2 hart=65537 state=-1 error=-4"));
	assert(!memcmp(instance, &before, sizeof(before)));
	firmware_error = 0;
	firmware_state = 3;
	mk_test_snapshot(instance, "exec-rejected");
	assert(queries == 9 && strstr(hsm_output, "sample=3 hart=7 state=3 error=0"));
	/* Null ownership must not lose orphan tracking or index by hart ID. */
	instance->cpus = NULL;
	mk_test_snapshot(instance, "exec-rejected");
	assert(queries == 11 && queried[9] == 7 && queried[10] == tracked[1]);
	instance->cpus_on_slot = NULL;
	mk_test_snapshot(instance, "exec-rejected");
	assert(queries == 11 && frees == 6);
}
int main(void)
{
	struct mk_instance instance = { .id=1, .instance_pool=(void *)1,
		.manifest_phys=4096, .ipi_phys=8192, .ipi_pages=2 };
	mk_instance_mem_free(&instance, (void *)12288, 4096);
	assert(frees == 1 && markers == 0);
	mk_test_resource_trace = true;
	mk_instance_mem_free(&instance, (void *)12288, 4096);
	assert(frees == 2 && markers == 1);
	assert(strstr(output, "kind=allocation") && strstr(output, "phys=3000"));
	mk_instance_free_boot_pages(&instance);
	assert(frees == 4 && markers == 3);
	assert(!instance.manifest_phys && !instance.ipi_phys && !instance.ipi_data);
	instance.id=2;
	mk_instance_mem_free(&instance, (void *)12288, 4096);
	assert(frees == 5 && markers == 3);
	instance.id=1;
	host.id=1;
	mk_instance_mem_free(&instance, (void *)12288, 4096);
	assert(frees == 6 && markers == 3);
	test_rejected_snapshots(&instance);
	puts("PASS: bounded read-only sparse/orphan HSM snapshots and release markers");
}
