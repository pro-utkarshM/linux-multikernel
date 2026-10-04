// SPDX-License-Identifier: GPL-2.0-only
/* Selector semantics only, not native firmware/domain proof. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#define SBI_HARTMASK_MAX_BITS 128
#define SBI_EDENIED (-4)
#define SBI_EINVAL (-3)
#define SBI_HSM_STATE_STOPPED 1
#define SBI_HSM_STATE_STOP_PENDING 3
#define MK_TEST_PRIME 0x80228328UL
typedef unsigned int u32;
typedef unsigned long ulong;
typedef bool spinlock_t;
#define SPIN_LOCK_INITIALIZER false
static void spin_lock(spinlock_t *p) { assert(!*p); *p = true; }
static void spin_unlock(spinlock_t *p) { assert(*p); *p = false; }
static u32 sbi_hartid_to_hartindex(u32 hart) { return hart == 65537 ? 0 : hart == 7 ? 1 : 128; }
#define sbi_printf(...) do { } while (0)
#define CSR_MHARTID 0
#define csr_read(csr) 3
#include "opensbi_test_hsm.h"

int main(void)
{
	int rc;
	assert(!mk_test_hsm_start(999, MK_TEST_PRIME, 0));
	rc = mk_test_hsm_start(65537, MK_TEST_PRIME, 0);
	if (MK_TEST_FAULT == 1 || MK_TEST_FAULT == 2) {
		assert(rc == (MK_TEST_FAULT == 1 ? SBI_EDENIED : SBI_EINVAL));
		assert(!mk_test_hsm_start(65537, MK_TEST_PRIME, 0));
	} else {
		assert(!rc);
		rc = mk_test_hsm_start(7, MK_TEST_PRIME, 0);
		assert(rc == (MK_TEST_FAULT == 3 ? SBI_EDENIED : 0));
	}
	assert(mk_test_hsm_status(65537, 1) == 1);
	rc = mk_test_hsm_start(65537, 0x88000000, 0x89000000);
	assert(rc == ((MK_TEST_FAULT == 4 || MK_TEST_FAULT == 8) ? SBI_EDENIED : 0));
	if (MK_TEST_FAULT == 8) {
		assert(mk_test_hsm_status(65537, 1) == 3);
		assert(mk_test_hsm_status(65537, 0) == 0);
		assert(mk_test_hsm_status(65537, -4) == -4);
		assert(mk_test_hsm_status(7, 1) == 1);
		assert(mk_test_hsm_status(999, 1) == 1);
		for (int i = 0; i < 100; i++)
			assert(mk_test_hsm_status(65537, 1) == 3);
		puts("PASS: firmware selector mode 8");
		return 0;
	}
	if (!rc)
		mk_test_hsm_started(65537, 0x88000000, 0x89000000);
	rc = mk_test_hsm_start(7, 0x88000000, 0x89000000);
	assert(rc == (MK_TEST_FAULT == 5 ? SBI_EDENIED : 0));
	if (MK_TEST_FAULT == 5) {
		assert(mk_test_hsm_start(7, 0x88000000, 0x89000000) == SBI_EDENIED);
		assert(!mk_test_hsm_start(7, 0x80201000, 0x81000000));
	}
	if (MK_TEST_FAULT == 6 || MK_TEST_FAULT == 7) {
		assert(mk_test_hsm_status(65537, 0) == 0);
		for (int i = 0; i < 32; i++)
			assert(mk_test_hsm_status(65537, 1) == 3);
		assert(mk_test_hsm_status(65537, 1) == (MK_TEST_FAULT == 6 ? 1 : 3));
	} else {
		assert(mk_test_hsm_status(65537, 1) == 1);
	}
	printf("PASS: firmware selector mode %d\n", MK_TEST_FAULT);
}
