#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
ulimit -c 0
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-native-irq-wake.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^static DECLARE_(WAIT_QUEUE_HEAD|COMPLETION)\(/ { print }
     /^static void callback_hold\(/ { copy = 1 }
     /^void mk_native_registry_detached\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/arch/x86/multikernel/native_rcu_gate.c" > "$build/irq-wake-production.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror -Wno-unused-parameter \
    -I"$build" "$test_dir/native_irq_wake_test.c" -o "$build/native_irq_wake_test"
"$build/native_irq_wake_test"
