#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
ulimit -c 0
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=${MK_SOURCE:-$(CDPATH= cd -- "$test_dir/../../../.." && pwd)}
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-riscv-tree.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
if test -f "$src/arch/riscv/multikernel/boot.c"; then
    sed '/^#include /d' "$src/arch/riscv/multikernel/boot.c" > "$build/boot.h"
else
    awk '/^int __weak mk_arch_boot_nodes\(/ { copy = 1 }
         copy { print }
         copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/dts.c" > "$build/boot.h"
fi
${CC:-cc} -std=gnu11 -Wall -Wextra -Werror -Wno-unused-parameter \
    -Wno-unused-function -Wno-unused-variable \
    -I"$build" -I"$src/scripts/dtc/libfdt" \
    "$test_dir/riscv_boot_tree_test.c" "$src"/scripts/dtc/libfdt/*.c -o "$build/test"
"$build/test"
