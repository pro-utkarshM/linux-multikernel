// SPDX-License-Identifier: GPL-2.0-only
/* Actual Image loader; allocation and extra-segment IO controlled. */
#include <endian.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <linux/align.h>

typedef uint32_t u32;
typedef uint64_t u64;
#include <asm/image.h>
#define SZ_2M 2097152UL
#define le64_to_cpu le64toh
#define IS_ENABLED(option) 0
#define ERR_PTR(n) ((void *)(intptr_t)(n))
#define KEXEC_BUF_MEM_UNKNOWN ULONG_MAX
#define pr_err(...) do { } while (0)
#define pr_info(...) do { } while (0)
enum { KEXEC_TYPE_DEFAULT, KEXEC_TYPE_CRASH, KEXEC_TYPE_MULTIKERNEL };
struct kimage { int type; unsigned long start; };
struct kexec_buf {
	struct kimage *image;
	void *buffer;
	unsigned long buf_min, buf_max, mem, memsz, bufsz, buf_align;
	bool top_down;
};
static unsigned int allocations, extras, checks, failures;
static unsigned long destination = 0xc0200000, allocated_size;
static int allocation_error, extra_error;
static int kexec_add_buffer(struct kexec_buf *buf)
{
	allocations++;
	allocated_size = buf->memsz;
	buf->mem = destination;
	return allocation_error;
}
static int extra_segments(void)
{
	extras++;
	return extra_error;
}
#define load_extra_segments(image, base, size, initrd, ilen, cmd, clen) \
	((void)(image), (void)(base), (void)(size), (void)(initrd), (void)(ilen), \
	 (void)(cmd), (void)(clen), extra_segments())
#include "image-production.h"

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
	struct riscv_image_header header = {
		.image_size = htole64(2048), .text_offset = htole64(SZ_2M),
	};
	struct kimage image = { .type = KEXEC_TYPE_DEFAULT };

	expect("ordinary length policy unchanged",
	       !image_load(&image, (char *)&header, 4096, NULL, 0, NULL, 0));
	image.type = KEXEC_TYPE_CRASH;
	expect("crash length policy unchanged",
	       !image_load(&image, (char *)&header, 4096, NULL, 0, NULL, 0));
	image.type = KEXEC_TYPE_MULTIKERNEL;
	allocations = extras = 0;
	expect("MK file must fit advertised Image size",
	       image_load(&image, (char *)&header, 4096, NULL, 0, NULL, 0) == ERR_PTR(-EINVAL));
	expect("bad size allocates nothing", !allocations && !extras);
	header.image_size = htole64(SZ_2M + 1);
	expect("valid MK Image", !image_load(&image, (char *)&header, 4096, NULL, 0, NULL, 0));
	expect("strict RWX PMD extent reserved", allocated_size == 2 * SZ_2M);
	expect("Image entry is allocated physical address", image.start == destination);
	destination++;
	expect("misaligned destination refused",
	       image_load(&image, (char *)&header, 4096, NULL, 0, NULL, 0) == ERR_PTR(-EINVAL));
	destination--;
	header.text_offset = htole64(4096);
	allocations = 0;
	expect("invalid RV64 text offset refused",
	       image_load(&image, (char *)&header, 4096, NULL, 0, NULL, 0) == ERR_PTR(-EINVAL));
	expect("bad offset allocates nothing", !allocations);
	header.text_offset = htole64(SZ_2M);
	header.image_size = htole64(ULONG_MAX);
	allocations = 0;
	expect("rounding overflow refused",
	       image_load(&image, (char *)&header, 4096, NULL, 0, NULL, 0) == ERR_PTR(-EOVERFLOW));
	expect("overflow allocates nothing", !allocations);
	header.image_size = htole64(SZ_2M);
	allocation_error = -ENOMEM;
	expect("grant allocation failure propagated",
	       image_load(&image, (char *)&header, 4096, NULL, 0, NULL, 0) == ERR_PTR(-ENOMEM));
	allocation_error = 0;
	extra_error = -ENOSPC;
	expect("extra segment failure propagated for generic rollback",
	       image_load(&image, (char *)&header, 4096, NULL, 0, NULL, 0) == ERR_PTR(-ENOSPC));
	printf("RISC-V Image: %u checks, %u failures\n", checks, failures);
	return failures ? 1 : 0;
}
