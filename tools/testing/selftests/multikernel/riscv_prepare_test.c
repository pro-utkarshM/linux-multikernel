// SPDX-License-Identifier: GPL-2.0-only
/* Real prepare function, controlled page/FDT/user-copy boundaries. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#define KEXEC_TYPE_MULTIKERNEL 2
#define KEXEC_TYPE_CRASH 1
#define unlikely(x) (x)
#define pr_err(...) do { } while (0)
struct fdt_header { unsigned int magic; char padding[60]; };
struct kimage_arch { unsigned long fdt_addr; };
struct kimage {
	struct kimage_arch arch;
	int type, nr_segments, file_mode;
	struct { unsigned long memsz, mem; void *buf; } segment[1];
	void *control_code_page;
};

static unsigned int probes, page_reads, executable;
static const unsigned char riscv_kexec_relocate[16] = { 1 };
static const unsigned int riscv_kexec_relocate_size = 16;

static int fdt_check_header(const struct fdt_header *h)
{
	probes++;
	return h->magic == 0xd00dfeed ? 0 : -EINVAL;
}

static void *page_address(void *page)
{
	page_reads++;
	return page;
}

static unsigned long page_size(void *page)
{
	return 4096;
}

static int set_memory_x(unsigned long address, int pages)
{
	assert(address && pages == 1);
	executable++;
	return 0;
}

static int copy_from_user(void *to, void *from, unsigned long size)
{
	memcpy(to, from, size);
	return 0;
}

#include "prepare-production.h"

int main(void)
{
	struct kimage image = { .type = KEXEC_TYPE_MULTIKERNEL };
	struct fdt_header header = { .magic = 0xd00dfeed };
	unsigned char control[4096] = { 0 };
	int ret = machine_kexec_prepare(&image);

	if (ret || probes || page_reads || executable) {
		fprintf(stderr,
			"FAIL: MK prepare must not require a load-time DTB or relocation page (%d)\n",
			ret);
		return 1;
	}
	image.type = 0;
	image.file_mode = 1;
	image.nr_segments = 1;
	image.segment[0].buf = &header;
	image.segment[0].memsz = sizeof(header) + 1;
	image.segment[0].mem = 0xc0200000;
	image.control_code_page = control;
	assert(!machine_kexec_prepare(&image));
	assert(probes == 1 && page_reads == 1 && executable == 1);
	assert(image.arch.fdt_addr == 0xc0200000 && control[0] == 1);
	image.arch.fdt_addr = 0;
	image.nr_segments = 0;
	assert(machine_kexec_prepare(&image) == -EINVAL);
	puts("PASS: MK bypasses load-time DTB/relocation; ordinary prepare preserved");
	return 0;
}
