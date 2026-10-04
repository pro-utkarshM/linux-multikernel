#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-riscv-elf.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^static void \*elf_kexec_load\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/arch/riscv/kernel/kexec_elf.c" > "$build/elf-production.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror -Wno-unused-parameter \
    -I"$build" "$test_dir/riscv_elf_test.c" -o "$build/test"
"$build/test"
