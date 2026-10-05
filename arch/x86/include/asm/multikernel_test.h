/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_MULTIKERNEL_TEST_H
#define _ASM_X86_MULTIKERNEL_TEST_H
#include <linux/types.h>
/* Disposable test branch only; no wire operation or production ABI. */
enum mk_native_point {
	MK_NATIVE_CONTROLLER_LOCKED = 1,
	MK_NATIVE_CPU_LOCKED,
	MK_NATIVE_CPU_BEFORE_ACK,
	MK_NATIVE_CPU_BUSY,
	MK_NATIVE_CPU_ACK_SENT,
	MK_NATIVE_QUIESCE_CLOSED,
	MK_NATIVE_QUIESCE_DRAINED,
	MK_NATIVE_CONTROLLER_ATTEMPT,
	MK_NATIVE_GATE_ENTER,
	MK_NATIVE_GATE_LEAVE,
	MK_NATIVE_GATE_TIMEOUT,
};
struct dentry;
struct mk_ipi_data;
struct mk_ipi_handler;
struct mutex;
void mk_native_gate_init(struct dentry *directory);
void mk_native_rcu_init(struct dentry *directory);
void mk_native_rcu_vector(bool entered);
void mk_native_rcu_boundary(unsigned long handler, unsigned int point);
void mk_native_rcu_consumed(unsigned int type, size_t size, u64 cookie);
u64 mk_native_rcu_tag(struct mk_ipi_data *data);
bool mk_native_registry_lock(struct mutex *lock);
void mk_native_registry_published(void *ctx, struct mk_ipi_handler *handler, void *type);
void mk_native_registry_detached(bool terminal);
void mk_native_registry_freed(unsigned long identity);
void mk_native_checkpoint(unsigned int point, u64 request, u64 cpu,
			  int result, unsigned int operation);
#endif
