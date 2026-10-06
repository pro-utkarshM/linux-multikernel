/* SPDX-License-Identifier: GPL-2.0-only */
/* Private test branch: default-off, host instance 1, consumed once under overlay lock. */
static unsigned int mk_test_manifest_mode;

static bool mk_test_manifest_take(struct mk_instance *instance, unsigned int mode)
{
	if (!mk_self || mk_self->id != 0 || !instance || instance->id != 1 ||
	    mk_test_manifest_mode != mode)
		return false;
	lockdep_assert_held(&mk_overlay_mutex);
	mk_test_manifest_mode = 0;
	pr_info("MK_TEST_MANIFEST fault=%u id=1\n", mode);
	return true;
}
