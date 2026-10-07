#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
ulimit -c 0
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=${MK_SOURCE:-$(CDPATH= cd -- "$test_dir/../../../.." && pwd)}
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-boot-nodes.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^static int mk_dt_emit_tree\(/ || /^int mk_dt_emit_boot_tree\(/ ||
     /^static int mk_dt_emit_instance\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/dts.c" > "$build/tree.h"
${CC:-cc} -std=gnu11 -Wall -Wextra -Werror -Wno-unused-parameter \
    -I"$build" -I"$src/scripts/dtc/libfdt" \
    "$test_dir/boot_nodes_test.c" "$src"/scripts/dtc/libfdt/*.c -o "$build/test"
"$build/test"
