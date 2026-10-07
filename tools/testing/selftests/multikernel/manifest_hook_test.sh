#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
ulimit -c 0
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=${MK_SOURCE:-$(CDPATH= cd -- "$test_dir/../../../.." && pwd)}
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-manifest-hook.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^struct mk_manifest_ctx / { copy = 1 }
     /^static int mk_manifest_chosen\(/ { copy = 1 }
     /^int mk_manifest_finalize\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/manifest.c" > "$build/under-test.h"
for variant in plain native; do
    native_flag=
    test "$variant" != native || native_flag=-DMK_NATIVE_TEST_KERNEL
    ${CC:-cc} $native_flag -std=gnu11 -Wall -Wextra -Werror \
        -Wno-unused-function -Wno-unused-variable \
        -I"$build" -I"$test_dir" -I"$src/scripts/dtc/libfdt" \
        "$test_dir/manifest_hook_test.c" "$src"/scripts/dtc/libfdt/*.c \
        -o "$build/test"
    "$build/test"
done
