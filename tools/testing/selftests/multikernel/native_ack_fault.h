/* SPDX-License-Identifier: GPL-2.0-only */
/* Private integration instrumentation: caller already matched the live tuple. */
static bool mk_test_lose_shutdown_ack(bool *armed, int self_id, u32 type,
				     u32 operation, u64 resource, u64 id, int result)
{
	if (!*armed || self_id || type != MK_MSG_SYSTEM ||
	    operation != MK_SYS_SHUTDOWN || !resource || !id || result)
		return false;
	*armed = false;
	return true;
}
