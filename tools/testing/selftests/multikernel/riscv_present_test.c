// SPDX-License-Identifier: GPL-2.0-only
/* Real SMP preparation must not turn possible unassigned harts present. */
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#define __init
#define for_each_possible_cpu(cpu) for ((cpu) = 0; (cpu) < 3; (cpu)++)
#define panic(...) abort()
static unsigned int present;
static bool spawned;
static void init_cpu_topology(void) { }
static void store_cpu_topology(unsigned int cpu) { (void)cpu; }
static void numa_store_cpu_info(unsigned int cpu) { (void)cpu; }
static void numa_add_cpu(unsigned int cpu) { (void)cpu; }
static unsigned int smp_processor_id(void) { return 0; }
static bool mk_riscv_cpu_assigned(unsigned int cpu) { return !spawned || cpu < 2; }
static void set_cpu_present(unsigned int cpu, bool yes)
{
	if (yes)
		present |= 1U << cpu;
	else
		present &= ~(1U << cpu);
}
#include "present.h"

int main(void)
{
	present = 1;
	smp_prepare_cpus(3);
	assert(present == 7);
	spawned = true;
	present = 7;
	smp_prepare_cpus(3);
	assert(present == 3);
	puts("PASS: host SMP unchanged; possible unassigned harts excluded before startup");
	return 0;
}
