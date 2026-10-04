// SPDX-License-Identifier: GPL-2.0-only
/* Actual ELF loader policy; ELF parsing/allocation boundaries controlled. */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#define ERR_PTR(n) ((void *)(intptr_t)(n))
#define KEXEC_TYPE_MULTIKERNEL 2
struct kimage { int type; unsigned long start; };
struct elfhdr { int unused; };
struct kexec_elf_info { int unused; };
static int builds, placements, loads, extras, frees;

static int kexec_build_elf_info(char *b, unsigned long n,
			      struct elfhdr *h, struct kexec_elf_info *i)
{
	builds++;
	return 0;
}

static int elf_find_pbase(struct kimage *image, unsigned long len,
			  struct elfhdr *h, struct kexec_elf_info *i,
			  unsigned long *old, unsigned long *new)
{
	placements++;
	return 0;
}

static int riscv_kexec_elf_load(struct kimage *image, struct elfhdr *h,
			      struct kexec_elf_info *i,
			      unsigned long old, unsigned long new)
{
	loads++;
	return 0;
}

static int load_extra_segments(struct kimage *image, unsigned long base,
			       unsigned long len, char *initrd, unsigned long ilen,
			       char *cmd, unsigned long clen)
{
	extras++;
	return 0;
}

static void kexec_free_elf_info(struct kexec_elf_info *i)
{
	frees++;
}

#include "elf-production.h"

int main(void)
{
	struct kimage image = { .type = KEXEC_TYPE_MULTIKERNEL };

	if (elf_kexec_load(&image, NULL, 0, NULL, 0, NULL, 0) != ERR_PTR(-EOPNOTSUPP) ||
	    builds || placements || loads || extras || frees) {
		fputs("FAIL: MK must reject ELF before parsing or allocating\n", stderr);
		return 1;
	}
	image.type = 0;
	assert(!elf_kexec_load(&image, NULL, 0, NULL, 0, NULL, 0));
	assert(builds == 1 && placements == 1 && loads == 1 && extras == 1 && frees == 1);
	puts("PASS: MK ELF refused before allocation; ordinary ELF unchanged");
	return 0;
}
