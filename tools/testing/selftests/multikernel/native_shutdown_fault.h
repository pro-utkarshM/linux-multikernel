/* SPDX-License-Identifier: GPL-2.0-only */
/* Private, default-off contention at the actual spawn syscore trylock. */
static bool mk_test_shutdown_contend;
static bool mk_test_shutdown_running, mk_test_shutdown_acquired;
static bool mk_test_shutdown_expired;
static DECLARE_COMPLETION(mk_test_shutdown_held);
static DECLARE_COMPLETION(mk_test_shutdown_release);
static DECLARE_COMPLETION(mk_test_shutdown_done);

static int __init mk_test_shutdown_setup(char *arg)
{
	return !kstrtobool(arg, &mk_test_shutdown_contend);
}
__setup("mk_test_shutdown_contend=", mk_test_shutdown_setup);

static int mk_test_shutdown_holder(void *unused)
{
	mk_test_shutdown_acquired = mutex_trylock(&mk_overlay_mutex);
	complete(&mk_test_shutdown_held);
	if (mk_test_shutdown_acquired) {
		mk_test_shutdown_expired = !wait_for_completion_timeout(
			&mk_test_shutdown_release, 5 * HZ);
		mutex_unlock(&mk_overlay_mutex);
	}
	complete(&mk_test_shutdown_done);
	return 0;
}

static void mk_test_shutdown_end(bool contended)
{
	if (!mk_test_shutdown_running)
		return;
	complete(&mk_test_shutdown_release);
	if (!wait_for_completion_timeout(&mk_test_shutdown_done, 5 * HZ) ||
	    !mk_test_shutdown_acquired || mk_test_shutdown_expired || !contended)
		pr_err("MK_TEST_SHUTDOWN_FAIL id=1 reason=unproven-contention\n");
	else
		pr_info("MK_TEST_SHUTDOWN_CONTENDED id=1 held=1 trylock=0 released=1\n");
	mk_test_shutdown_running = false;
}

static bool mk_test_shutdown_begin(void)
{
	/* One terminal shutdown only; host and other instances are untouched. */
	if (!mk_test_shutdown_contend || !mk_spawned() || !mk_self || mk_self->id != 1)
		return true;
	if (IS_ERR(kthread_run(mk_test_shutdown_holder, NULL, "mk-test-hold"))) {
		pr_err("MK_TEST_SHUTDOWN_FAIL id=1 reason=thread-create\n");
		return false;
	}
	mk_test_shutdown_running = true;
	if (wait_for_completion_timeout(&mk_test_shutdown_held, 5 * HZ) &&
	    mk_test_shutdown_acquired)
		return true;
	mk_test_shutdown_end(false);
	return false;
}
