/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef MK_NATIVE_RESOURCE_TRACE_H
#define MK_NATIVE_RESOURCE_TRACE_H

/* Private test integration only; not a production management interface. */
struct mk_instance;
void mk_test_snapshot(struct mk_instance *instance, const char *phase);

#endif
