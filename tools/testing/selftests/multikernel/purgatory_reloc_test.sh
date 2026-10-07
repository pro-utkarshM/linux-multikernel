#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Host-side check of the selected kernel's actual RISC-V relocation handler.
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=${1:?usage: purgatory_reloc_test.sh KERNEL_SOURCE}
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-purgatory-reloc.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^#define RISCV_IMM_BITS/ { copy = 1 }
     /^int load_extra_segments\(/ { exit }
     /^static int load_multikernel_segments\(/ { exit }
     copy { print }' "$src/arch/riscv/kernel/machine_kexec_file.c" \
    > "$build/reloc-production.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror -Wno-unused-function -Wno-sign-compare \
    -I"$build" "$test_dir/purgatory_reloc_test.c" -o "$build/reloc-test"
"$build/reloc-test"
