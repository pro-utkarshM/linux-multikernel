#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
ulimit -c 0
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-placement.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^static int kexec_alloc_multikernel\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/kexec_file.c" > "$build/under-test.h"
for variant in plain native; do
    native_flag=
    test "$variant" != native || native_flag=-DMK_NATIVE_TEST_KERNEL
    ${CC:-cc} $native_flag -std=gnu11 -Wall -Wextra -Werror \
        -I"$build" -I"$test_dir" "$test_dir/placement_test.c" -o "$build/test"
    "$build/test"
done
