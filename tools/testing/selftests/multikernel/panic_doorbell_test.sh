#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
ulimit -c 0
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=${MK_SOURCE:-$(CDPATH= cd -- "$test_dir/../../../.." && pwd)}
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-panic-doorbell.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^static void mk_riscv_shutdown_prepare\(/ { copy = 1 }
     /^static const struct syscore_ops mk_riscv_syscore_ops =/ { copy = 1 }
     /^static struct syscore mk_riscv_syscore =/ { copy = 1 }
     /^static int mk_riscv_receiver_offline\(/ { copy = 1 }
     /^static int __init mk_riscv_doorbell_init\(/ { copy = 1 }
     /^void mk_riscv_notify_parent_halted\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/arch/riscv/multikernel/doorbell.c" > "$build/notice.h"
${CC:-cc} -std=gnu11 -Wall -Wextra -Werror -Wno-unused-function \
    -Wno-unused-variable -Wno-unused-parameter \
    -I"$build" "$test_dir/panic_doorbell_test.c" -o "$build/test"
"$build/test"
