#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-riscv-image.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^static void \*image_load\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/arch/riscv/kernel/kexec_image.c" > "$build/image-production.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror -I"$build" -I"$src/tools/include" \
    -I"$src/arch/riscv/include" "$test_dir/riscv_image_test.c" -o "$build/riscv_image_test"
"$build/riscv_image_test"
