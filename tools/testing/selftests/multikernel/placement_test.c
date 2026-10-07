// SPDX-License-Identifier: GPL-2.0-only
/* Extracted allocator with controlled allocation/address-conversion boundaries. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define SZ_2M (2UL * 1024 * 1024)
#define PAGE_SIZE 4096UL
#define IS_ALIGNED(value, align) (!((value) & ((align) - 1)))
#define KEXEC_TYPE_MULTIKERNEL 2
#define pr_info(...) do { } while (0)
typedef unsigned long phys_addr_t;

struct kimage { int type, mk_id; };
struct kexec_buf {
	struct kimage *image;
	unsigned long memsz, buf_align, buf_min, buf_max, mem;
};

static struct kimage image = { KEXEC_TYPE_MULTIKERNEL, 1 };
static void *allocation = (void *)(uintptr_t)0x10000000;
static phys_addr_t physical;
static unsigned int frees, lock_checks;
static bool allocation_failed, overlaps;
static struct { int id; } host;
static typeof(host) *mk_self = &host;
static int mk_overlay_mutex;
static bool mk_test_bad_placement;
#define lockdep_assert_held(lock) do { \
	assert((lock) == &mk_overlay_mutex); lock_checks++; \
} while (0)

static void *mk_kimage_alloc(struct kimage *img, size_t size, unsigned long align)
{
	assert(img == &image && size == 2 * SZ_2M && align >= PAGE_SIZE);
	return allocation_failed ? NULL : allocation;
}

static phys_addr_t virt_to_phys(void *ptr)
{
	assert(ptr == allocation);
	return physical;
}

static void mk_kimage_free(struct kimage *img, void *ptr, size_t size)
{
	assert(img == &image && ptr == allocation && size == 2 * SZ_2M);
	frees++;
}

static bool kimage_is_destination_range(struct kimage *img,
				       phys_addr_t start, phys_addr_t end)
{
	assert(img == &image && start == physical && end == physical + 2 * SZ_2M - 1);
	return overlaps;
}

#ifdef MK_NATIVE_TEST_KERNEL
#include "native_placement_fault.h"
#endif
#include "under-test.h"

static struct kexec_buf reset(void)
{
	physical = 0x90000000;
	frees = lock_checks = 0;
	allocation_failed = overlaps = mk_test_bad_placement = false;
	host.id = 0;
	mk_self = &host;
	image.type = KEXEC_TYPE_MULTIKERNEL;
	image.mk_id = 1;
	return (struct kexec_buf) { &image, 2 * SZ_2M, SZ_2M, physical,
				   physical + 256 * SZ_2M - 1, ~0UL };
}

int main(void)
{
	struct kexec_buf buf = reset();

	(void)mk_overlay_mutex;
	assert(kexec_alloc_multikernel(&buf) == 0 && buf.mem == physical && !frees);
	buf = reset();
	physical |= PAGE_SIZE;
	assert(kexec_alloc_multikernel(&buf) == -ENOMEM && frees == 1 && buf.mem == ~0UL);
	buf = reset();
	allocation_failed = true;
	assert(kexec_alloc_multikernel(&buf) == -ENOMEM && !frees && buf.mem == ~0UL);
	buf = reset();
	buf.buf_min = physical + SZ_2M;
	assert(kexec_alloc_multikernel(&buf) == -ENOMEM && frees == 1 && buf.mem == ~0UL);
	buf = reset();
	buf.buf_max = physical + SZ_2M - 1;
	assert(kexec_alloc_multikernel(&buf) == -ENOMEM && frees == 1 && buf.mem == ~0UL);
	buf = reset();
	overlaps = true;
	assert(kexec_alloc_multikernel(&buf) == -EBUSY && frees == 1 && buf.mem == ~0UL);
	buf = reset();
	mk_test_bad_placement = true;
#ifdef MK_NATIVE_TEST_KERNEL
	assert(kexec_alloc_multikernel(&buf) == -ENOMEM && frees == 1 && buf.mem == ~0UL);
	assert(!mk_test_bad_placement && lock_checks == 1);
	assert(kexec_alloc_multikernel(&buf) == 0 && buf.mem == physical && frees == 1);
	/* Off-target allocations must not consume the one-shot selector. */
	for (unsigned int target = 0; target < 5; target++) {
		buf = reset();
		mk_test_bad_placement = true;
		switch (target) {
		case 0:
			host.id = 1;
			break;
		case 1:
			mk_self = NULL;
			break;
		case 2:
			image.mk_id = 2;
			break;
		case 3:
			image.type = 0;
			break;
		case 4:
			buf.buf_align = PAGE_SIZE;
			break;
		}
		assert(kexec_alloc_multikernel(&buf) == 0 && buf.mem == physical && !frees);
		assert(mk_test_bad_placement && !lock_checks);
	}
#else
	assert(kexec_alloc_multikernel(&buf) == 0 && buf.mem == physical && !frees);
	assert(mk_test_bad_placement && !lock_checks);
#endif
	puts("PASS: placement rejection, exact rollback and one-shot isolation");
	return 0;
}
