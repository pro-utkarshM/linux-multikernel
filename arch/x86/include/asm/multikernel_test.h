/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_MULTIKERNEL_TEST_H
#define _ASM_X86_MULTIKERNEL_TEST_H
#include <linux/types.h>
#include <linux/spinlock_types.h>
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
	MK_NATIVE_CONTROLLER_CONTENDED,
};
struct dentry;
struct mk_ipi_data;
struct mk_ipi_handler;
struct mutex;
struct mk_instance;
struct kimage;
struct work_struct;
struct completion;
void mk_native_gate_init(struct dentry *directory);
void mk_native_controller_lock(struct mutex *lock, u64 request);
void mk_native_drain_wait(bool waiting);
void mk_native_rcu_init(struct dentry *directory);
void mk_native_rcu_vector(bool entered);
bool mk_native_in_vector(void);
void mk_native_rcu_boundary(unsigned long handler, unsigned int point);
void mk_native_rcu_consumed(unsigned int type, size_t size, u64 cookie);
u64 mk_native_rcu_tag(struct mk_ipi_data *data);
bool mk_native_registry_lock(struct mutex *lock);
void mk_native_registry_published(void *ctx, struct mk_ipi_handler *handler, void *type);
void mk_native_registry_detached(bool terminal);
void mk_native_registry_freed(unsigned long identity);
void mk_native_tty_init(struct dentry *directory);
void mk_native_tty_receive(void *conn, void *buffer, u32 id, const char *data, size_t size);
bool mk_native_tty_close_lock(void *conn, raw_spinlock_t *lock, unsigned long *flags);
void mk_native_tty_boundary(unsigned long identity, unsigned int point);
bool mk_native_tty_worker(void *conn);
void mk_native_tty_flush_begin(void *conn, struct work_struct *work);
void mk_native_tty_flush_barrier(struct work_struct *work, struct completion *done);
void mk_native_tty_completion_wait(struct completion *done);
void mk_native_spawn_tty_init(struct dentry *directory);
bool mk_native_spawn_tty_begin(struct work_struct *work);
void mk_native_spawn_tty_chunk(unsigned int count);
void mk_native_spawn_tty_inserted(unsigned int count);
void mk_native_spawn_tty_hangup(bool flushed);
void mk_native_spawn_tty_end(bool observed);
bool mk_native_spawn_tty_queue(struct work_struct *work);
void mk_native_spawn_tty_rx(unsigned int size, unsigned int accepted, unsigned int queued);
void mk_native_spawn_tty_shutdown(struct work_struct *work, bool done, unsigned int lost);
void mk_native_spawn_tty_activate(void);
void mk_native_spawn_tty_barrier(struct work_struct *work, struct completion *done, bool from_cancel);
void mk_native_spawn_tty_wait(struct completion *done);
void mk_native_writer_init(struct dentry *directory);
void mk_native_writer_claim(struct mk_instance *instance, void *data, size_t size);
bool mk_native_writer_deactivate_lock(struct mk_instance *instance, unsigned long *flags);
void mk_native_writer_boundary(struct mk_instance *instance, unsigned int point);
void mk_native_writer_segments(struct mk_instance *instance, struct kimage *image);
void mk_native_destroy_init(struct dentry *directory);
void mk_native_destroy_hold(struct mk_instance *instance, void *data, size_t size);
void mk_native_destroy_boundary(unsigned long identity, unsigned int point);
void mk_native_destroy_retired(struct mk_instance *instance);
void mk_native_checkpoint(unsigned int point, u64 request, u64 cpu,
			  int result, unsigned int operation);
#endif
