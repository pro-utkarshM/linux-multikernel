/* SPDX-License-Identifier: GPL-2.0-only */
/* Private test branch: never change the allocation pointer used for rollback. */
static phys_addr_t mk_test_placement(struct kexec_buf *kbuf, phys_addr_t original)
{
	phys_addr_t injected;

	if (!mk_test_bad_placement || !mk_self || mk_self->id != 0 ||
	    kbuf->image->type != KEXEC_TYPE_MULTIKERNEL || kbuf->image->mk_id != 1 ||
	    kbuf->buf_align != SZ_2M || !IS_ALIGNED(original, SZ_2M))
		return original;
	lockdep_assert_held(&mk_overlay_mutex);
	mk_test_bad_placement = false;
	injected = original | PAGE_SIZE;
	pr_info("MK_TEST_PLACEMENT id=1 original=0x%llx injected=0x%llx size=%lu align=0x%lx\n",
		(unsigned long long)original, (unsigned long long)injected,
		kbuf->memsz, kbuf->buf_align);
	return injected;
}
