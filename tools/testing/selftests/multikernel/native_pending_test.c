// SPDX-License-Identifier: GPL-2.0-only
/* Real pending definitions; only allocator, lock and scheduler boundaries. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/list.h>
#include <linux/err.h>
#define u64 __u64
#define U64_MAX (~(u64)0)
#define GFP_KERNEL 0
#define kzalloc(n, flags) calloc(1, n)
#define kfree free
#define DEFINE_SPINLOCK(name) bool name
#define spin_lock_irqsave(lock, flags) do { assert(!*(lock)); *(lock) = true; (flags) = 0; } while (0)
#define spin_unlock_irqrestore(lock, flags) do { assert(*(lock)); *(lock) = false; (void)(flags); } while (0)
#define msecs_to_jiffies(ms) (ms)
#define pr_err(...) do { } while (0)
#define MK_MSG_SYSTEM 5
#define MK_SYS_SHUTDOWN 1
static bool mk_test_drop_shutdown_ack;
static struct { int id; } host = { .id = 0 }, *mk_self = &host;
static unsigned int drops;
static void drop_log(void);
#define pr_info(...) drop_log()
struct completion { bool done; };
static void init_completion(struct completion *c) { c->done = false; }
static void complete(struct completion *c) { c->done = true; }
static unsigned long wait_for_completion_timeout(struct completion *c, unsigned long timeout)
{ return c->done ? (timeout ? timeout : 1) : 0; }
#if __has_include("native_ack_fault.h")
#include "native_ack_fault.h"
#endif
#include "pending.h"
static void drop_log(void) { assert(!mk_pending_msgs_lock); drops++; }
static struct mk_pending_msg *add(u32 type, u32 op, u64 resource)
{
	struct mk_pending_msg *p = mk_msg_pending_add(type, op, resource);
	assert(!IS_ERR(p));
	return p;
}
static void reply(struct mk_pending_msg *p, int result)
{ mk_msg_pending_complete(p->msg_type, p->operation, p->resource_id, p->msg_id, result); }
int main(void)
{
	struct mk_pending_msg *p;
	p = add(5, 1, 65537);
	reply(p, 0);
	assert(mk_msg_pending_wait(p, 30000) == 0 && drops == 0);
	mk_test_drop_shutdown_ack = true;
	p = add(5, 1, 65537);
	mk_msg_pending_complete(5, 1, 65537, 0, 0);
	mk_msg_pending_complete(5, 1, 7, p->msg_id, 0);
	mk_msg_pending_complete(6, 1, 65537, p->msg_id, 0);
	mk_msg_pending_complete(5, 2, 65537, p->msg_id, 0);
	mk_msg_pending_complete(5, 1, 65537, p->msg_id + 1, 0);
	assert(mk_test_drop_shutdown_ack && drops == 0);
	reply(p, 0);
	assert(mk_msg_pending_wait(p, 30000) == -ETIMEDOUT);
	assert(drops == 1 && !mk_test_drop_shutdown_ack);
	p = add(5, 1, 65537);
	reply(p, 0);
	assert(mk_msg_pending_wait(p, 30000) == 0 && drops == 1);
	mk_test_drop_shutdown_ack = true;
	p = add(6, 1, 65537);
	reply(p, 0);
	assert(mk_msg_pending_wait(p, 30000) == 0 && mk_test_drop_shutdown_ack);
	p = add(5, 1, 65537);
	reply(p, -EIO);
	assert(mk_msg_pending_wait(p, 30000) == -EIO && mk_test_drop_shutdown_ack);
	host.id = 1;
	p = add(5, 1, 65537);
	reply(p, 0);
	assert(mk_msg_pending_wait(p, 30000) == 0 && mk_test_drop_shutdown_ack);
	host.id = 0;
	p = add(5, 1, 65537);
	{ u64 id = p->msg_id; mk_msg_pending_cancel(p);
	  mk_msg_pending_complete(5, 1, 65537, id, 0); }
	assert(mk_test_drop_shutdown_ack && drops == 1);
	mk_test_drop_shutdown_ack = false;
	p = add(5, 1, 65537);
	reply(p, 0);
	mk_test_drop_shutdown_ack = true;
	reply(p, 0);
	assert(mk_msg_pending_wait(p, 30000) == 0 && mk_test_drop_shutdown_ack);
	assert(list_empty(&mk_pending_msgs) && !mk_pending_msgs_lock);
	puts("PASS: actual pending ACK fault matching/default-off/one-shot/retirement");
}
