#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
ulimit -c 0
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=${MK_SOURCE:-$(CDPATH= cd -- "$test_dir/../../../.." && pwd)}
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-sbi-doorbell.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^static void sbi_ipi_handle\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/arch/riscv/kernel/sbi-ipi.c" > "$build/irq.h"
transport="$src/arch/riscv/multikernel/doorbell.c"
test -f "$transport" || transport="$src/arch/riscv/multikernel/spawn.c"
awk '/^void mk_arch_send_ipi\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$transport" > "$build/send.h"
awk '/^bool mk_riscv_inbox_cpu\(/ || /^static int mk_riscv_receiver_offline\(/ ||
     /^static int __init mk_riscv_doorbell_init\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$transport" > "$build/receiver.h"
${CC:-cc} -std=gnu11 -Wall -Wextra -Werror -Wno-unused-parameter \
    -Wno-unused-function -I"$build" "$test_dir/sbi_doorbell_test.c" -o "$build/test"
"$build/test"
