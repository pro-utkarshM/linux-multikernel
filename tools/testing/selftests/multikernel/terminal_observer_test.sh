#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=${MK_SOURCE:-$(CDPATH= cd -- "$test_dir/../../../.." && pwd)}
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-terminal-observer.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^void mk_native_shutdown_observe\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/arch/x86/multikernel/native_process_gate.c" > "$build/observer.h"
test -s "$build/observer.h" || { echo 'FAIL: terminal observer absent'; exit 1; }
${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror -I"$build" \
    "$test_dir/terminal_observer_test.c" -o "$build/test"
"$build/test"
