// SPDX-License-Identifier: GPL-2.0-only
/* Real emitter; a stopped lock owner must never make the observer wait. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define READ_ONCE(x) (x)
#define raw_spin_trylock_irqsave(lock, flags) ((void)(lock), (flags) = 0, lock_ok)
#define raw_spin_unlock_irqrestore(lock, flags) ((void)(lock), (void)(flags))
#define scnprintf snprintf
static bool available = true, lock_ok = true, shutdown_busy = true;
static bool gate_active = true, gate_released, overflow;
static unsigned int active_point = 1;
static unsigned long long gate_deadline_ns = 200, terminal_nonce = 0x1234567890abcdef;
static int event_lock;
static struct { int id; } self = {1}, *mk_self = &self;
static char output[512];
static size_t used;
static uint64_t ktime_get_mono_fast_ns(void) { return 100; }
static void outb(unsigned char byte, unsigned short port)
{
	assert(port == 0xe9 && used < sizeof(output) - 1);
	output[used++] = byte;
	output[used] = 0;
}
#include "observer.h"

int main(void)
{
	mk_native_shutdown_observe(false, false, false);
	assert(strstr(output, "\"nonce\":\"1234567890abcdef\""));
	assert(strstr(output, "\"notify\":0") && strstr(output, "\"observed\":1"));
	assert(strstr(output, "\"active\":1") && strstr(output, "\"valid\":1"));
	used = 0;
	gate_deadline_ns = 99;
	mk_native_shutdown_observe(false, false, false);
	assert(strstr(output, "\"valid\":0"));
	used = 0;
	lock_ok = false;
	mk_native_shutdown_observe(false, true, false);
	assert(strstr(output, "\"observed\":0") && strstr(output, "\"panic\":1"));
	used = 0;
	available = false;
	mk_native_shutdown_observe(false, true, false);
	assert(!used);
	available = true;
	self.id = 0;
	mk_native_shutdown_observe(false, true, false);
	assert(!used);
	puts("terminal observer: PASS (bounded output, expired gate, held lock, opt-in)");
	return 0;
}
