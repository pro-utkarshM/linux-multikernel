#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-native-observation.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^static (bool boundary_seen|int status_show)\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/arch/x86/multikernel/native_rcu_gate.c" > "$build/observation-production.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror -Wno-unused-parameter -pthread \
    -I"$build" "$test_dir/native_observation_test.c" -o "$build/native_observation_test"
"$build/native_observation_test"
