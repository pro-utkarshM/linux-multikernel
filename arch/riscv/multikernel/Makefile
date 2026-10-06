# SPDX-License-Identifier: GPL-2.0-only

obj-y += spawn.o entry.o
# Modern #27 adapter lives only on the test integration branch.
obj-y += boot.o
obj-y += doorbell.o
# Private integration-only shutdown fault; runtime selector defaults off.
CFLAGS_doorbell.o += -DMK_NATIVE_TEST_KERNEL -I$(srctree)/tools/testing/selftests/multikernel
