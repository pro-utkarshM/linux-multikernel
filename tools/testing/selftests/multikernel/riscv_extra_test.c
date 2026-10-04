// SPDX-License-Identifier: GPL-2.0-only
/* Actual extra-segment loader; allocation, ordinary FDT and purgatory controlled. */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#define CONFIG_ARCH_SUPPORTS_KEXEC_PURGATORY 1
#define KEXEC_TYPE_DEFAULT 0
#define KEXEC_TYPE_MULTIKERNEL 2
#define KEXEC_BUF_MEM_UNKNOWN ULONG_MAX
#define PAGE_SIZE 4096
#define pr_err(...) do { } while (0)
#define kexec_dprintk(...) do { } while (0)
#define kfree free
#define kvfree(p) do { } while (0)
struct kimage {
	int type;
	struct {
		void *fdt;
		unsigned long fdt_addr, initrd_start, initrd_size;
	} arch;
};
struct kexec_buf {
	struct kimage *image;
	void *buffer;
	unsigned long buf_min, buf_max, mem, memsz, bufsz, buf_align;
	bool top_down;
};
static unsigned int allocations, fdt_calls, purgatories, symbols, checks, failures;
static int allocation_error;
static char fake_fdt[64];
static int kexec_add_buffer(struct kexec_buf *buf)
{
	allocations++;
	buf->mem = 0xd0400000;
	return allocation_error;
}
static void *of_kexec_alloc_and_setup_fdt(struct kimage *image, unsigned long base,
	unsigned long length, char *cmdline, int flags)
{
	fdt_calls++;
	return fake_fdt;
}
static int fdt_pack(void *p) { return 0; }
static unsigned int fdt_totalsize(void *p) { return sizeof(fake_fdt); }
static int kexec_load_purgatory(struct kimage *image, struct kexec_buf *buf)
{
	purgatories++;
	return 0;
}
static int kexec_purgatory_get_set_symbol(struct kimage *image, const char *name,
	void *value, size_t size, int mode)
{
	symbols++;
	return 0;
}
#include "extra-production.h"
static void expect(const char *name, bool passed)
{
	checks++;
	if (!passed) {
		fprintf(stderr, "FAIL %s\n", name);
		failures++;
	}
}
int main(void)
{
	struct kimage image = { .type = KEXEC_TYPE_MULTIKERNEL };
	char initrd[16];
	int ret;

	ret = load_extra_segments(&image, 0xd0000000, 0x200000, initrd, sizeof(initrd), "a", 2);
	expect("MK initrd load succeeds", !ret);
	expect("MK never loads purgatory or patches its symbols", !purgatories && !symbols);
	expect("MK never clones host FDT at file load", !fdt_calls && !image.arch.fdt);
	expect("MK only allocates initrd segment", allocations == 1);
	expect("MK records physical initrd extent", image.arch.initrd_start == 0xd0400000 &&
	       image.arch.initrd_size == sizeof(initrd));
	allocations = fdt_calls = purgatories = symbols = 0;
	image = (struct kimage) { .type = KEXEC_TYPE_MULTIKERNEL };
	expect("MK no-initrd load", !load_extra_segments(&image, 0xd0000000, 0x200000, NULL, 0, NULL, 0));
	expect("no-initrd needs no extra segment", !allocations && !fdt_calls && !purgatories);
	allocation_error = -ENOMEM;
	expect("initrd allocation failure propagated",
	       load_extra_segments(&image, 0xd0000000, 0x200000, initrd, sizeof(initrd), NULL, 0) == -ENOMEM);
	expect("failed initrd does not publish metadata", !image.arch.initrd_start && !image.arch.initrd_size);
	allocation_error = 0;
	allocations = fdt_calls = purgatories = symbols = 0;
	image = (struct kimage) { .type = KEXEC_TYPE_DEFAULT };
	expect("ordinary extra loader unchanged",
	       !load_extra_segments(&image, 0xd0000000, 0x200000, initrd, sizeof(initrd), "a", 2));
	expect("ordinary still loads purgatory and host FDT", purgatories == 1 && symbols == 1 &&
	       fdt_calls == 1 && image.arch.fdt == fake_fdt && allocations == 2);
	printf("RISC-V extra segments: %u checks, %u failures\n", checks, failures);
	return failures ? 1 : 0;
}
