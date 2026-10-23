#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
ulimit -c 0
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=${MK_SOURCE:-$(CDPATH= cd -- "$test_dir/../../../.." && pwd)}
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-riscv-present.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^void __init smp_prepare_cpus\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/arch/riscv/kernel/smpboot.c" > "$build/present.h"
${CC:-cc} -std=gnu11 -Wall -Wextra -Werror -Wno-unused-function -Wno-sign-compare \
    -I"$build" "$test_dir/riscv_present_test.c" -o "$build/test"
"$build/test"
