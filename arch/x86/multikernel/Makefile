# SPDX-License-Identifier: GPL-2.0
#
# Makefile for multikernel spawn support
#

obj-y += spawn.o direct_boot.o head_64.o e820.o
obj-$(CONFIG_MK_X86_NATIVE_CONFIRM_TEST) += native_confirm_test.o
obj-$(CONFIG_MK_X86_NATIVE_CONCURRENCY_TEST) += native_concurrency_test.o native_process_gate.o
obj-$(CONFIG_MK_X86_NATIVE_CONCURRENCY_TEST) += native_rcu_gate.o
obj-$(CONFIG_MK_X86_NATIVE_CONCURRENCY_TEST) += native_mktty_gate.o
obj-$(CONFIG_MK_X86_NATIVE_CONCURRENCY_TEST) += native_spawn_tty_gate.o
obj-$(CONFIG_MK_X86_NATIVE_CONCURRENCY_TEST) += native_writer_gate.o
obj-$(CONFIG_MK_X86_NATIVE_CONCURRENCY_TEST) += native_destroy_gate.o
