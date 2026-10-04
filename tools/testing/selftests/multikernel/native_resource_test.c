// SPDX-License-Identifier: GPL-2.0-only
/* Real free-site definitions; allocator/printing substituted at boundaries. */
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
typedef unsigned long phys_addr_t;
#define MK_MANIFEST_SIZE 4096
#define PAGE_SHIFT 12
struct mk_shared_data { char data[8192]; };
struct mk_instance {
	int id, state;
	void *instance_pool, *kimage, *ctrl_va, *ipi_data;
	unsigned long ctrl_phys, manifest_phys, ipi_phys;
	size_t pool_size;
	unsigned int ipi_pages;
	void *cpus, *cpus_on_slot;
};
static struct { int id; } host = { 0 }, *mk_self = &host;
static bool mk_overlay_mutex = true;
#define lockdep_assert_held(lock) assert(*(lock))
static unsigned int frees, markers;
static char output[2048];
static void print_marker(const char *format, ...);
#define pr_info(...) print_marker(__VA_ARGS__)
static const char *mk_state_to_string(int state) { (void)state; return "failed"; }
static unsigned int mk_cpu_set_count(void *cpus) { return cpus ? 2 : 0; }
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
	markers++;
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
	puts("PASS: actual allocation/ring/manifest release marker sites/default-off/target");
}
