#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-native-tty-observation.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^(bool mk_native_tty_worker|void mk_native_tty_flush_begin)\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/arch/x86/multikernel/native_mktty_gate.c" > "$build/tty-observation-production.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror -Wno-unused-parameter \
    -I"$build" "$test_dir/native_tty_observation_test.c" -o "$build/test"
"$build/test"
