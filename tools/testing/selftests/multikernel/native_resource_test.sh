#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-native-resource.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^typedef u64 mk_phys_cpu_t;/ { copy = 1 }
     /^\/\*\*$/ && copy && seen { exit }
     copy { print; seen = 1 }' "$src/include/linux/multikernel.h" > "$build/resource-types.h"
awk '/^(static void mk_instance_free_boot_pages|void mk_instance_mem_free)\(/ {copy=1}
     copy {print}
     copy && /^}/ {copy=0}' "$src/kernel/multikernel/core.c" > "$build/resource-sites.h"
${CC:-cc} ${CFLAGS:-} -DMK_NATIVE_TEST_KERNEL -DCONFIG_RISCV -std=gnu11 -Wall -Wextra -Werror \
    -Wno-unused-function -Wno-unused-variable -I"$build" -I"$test_dir" \
    "$test_dir/native_resource_test.c" -o "$build/test"
"$build/test"
