/* SPDX-License-Identifier: BSD-2-Clause */
/* QEMU test-only selectors. Mode 0 leaves firmware behavior unchanged. */
#ifndef MK_TEST_FAULT
#define MK_TEST_FAULT 0
#endif
#ifndef MK_TEST_PRIME
#error "derive MK_TEST_PRIME from the frozen host ELF, never use an old address"
#endif

static spinlock_t mk_test_lock = SPIN_LOCK_INITIALIZER;
static bool mk_test_primed[SBI_HARTMASK_MAX_BITS];
static bool mk_test_running[SBI_HARTMASK_MAX_BITS];
static u32 mk_test_polls[SBI_HARTMASK_MAX_BITS];
static u32 mk_test_prime_calls, mk_test_image_calls;
static bool mk_test_rejected;

static int mk_test_hsm_start(u32 hart, ulong entry, ulong opaque)
{
	u32 index = sbi_hartid_to_hartindex(hart);
	int ret = 0;

	if (!MK_TEST_FAULT || index >= SBI_HARTMASK_MAX_BITS)
		return 0;
	spin_lock(&mk_test_lock);
	if (entry == MK_TEST_PRIME && !opaque) {
		mk_test_prime_calls++;
		if (!mk_test_rejected &&
		    ((MK_TEST_FAULT == 1 || MK_TEST_FAULT == 2) ||
		     (MK_TEST_FAULT == 3 && mk_test_prime_calls == 2)))
			ret = MK_TEST_FAULT == 2 ? SBI_EINVAL : SBI_EDENIED;
		if (!ret)
			mk_test_primed[index] = true;
	} else if (mk_test_primed[index] && opaque) {
		mk_test_image_calls++;
		if (!mk_test_rejected &&
		    ((MK_TEST_FAULT == 4 && mk_test_image_calls == 1) ||
		     (MK_TEST_FAULT == 5 && mk_test_image_calls == 2)))
			ret = SBI_EDENIED;
	}
	if (ret)
		mk_test_rejected = true;
	spin_unlock(&mk_test_lock);
	if (ret)
		sbi_printf("MK_FW_REJECT mode=%u hart=%u entry=0x%lx error=%d\n",
			   MK_TEST_FAULT, hart, entry, ret);
	return ret;
}

static void mk_test_hsm_started(u32 hart, ulong entry, ulong opaque)
{
	u32 index = sbi_hartid_to_hartindex(hart);

	if (!MK_TEST_FAULT || index >= SBI_HARTMASK_MAX_BITS)
		return;
	spin_lock(&mk_test_lock);
	if (entry != MK_TEST_PRIME && opaque && mk_test_primed[index])
		mk_test_running[index] = true;
	spin_unlock(&mk_test_lock);
}

static int mk_test_hsm_status(u32 hart, int state)
{
	u32 index = sbi_hartid_to_hartindex(hart);
	bool report = false;
	int ret = state;

	if ((MK_TEST_FAULT != 6 && MK_TEST_FAULT != 7) ||
	    index >= SBI_HARTMASK_MAX_BITS || state != SBI_HSM_STATE_STOPPED)
		return state;
	spin_lock(&mk_test_lock);
	if (mk_test_running[index] &&
	    (MK_TEST_FAULT == 7 || mk_test_polls[index] < 32)) {
		report = !mk_test_polls[index];
		if (mk_test_polls[index] < 32)
			mk_test_polls[index]++;
		ret = SBI_HSM_STATE_STOP_PENDING;
	}
	spin_unlock(&mk_test_lock);
	if (report)
		sbi_printf("MK_FW_PENDING mode=%u hart=%u actual=1 reported=3\n",
			   MK_TEST_FAULT, hart);
	return ret;
}
