#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-fw-selector.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
for mode in 0 1 2 3 4 5 6 7; do
    ${CC:-cc} -std=gnu11 -Wall -Wextra -Werror -DMK_TEST_FAULT="$mode" \
        -I"$test_dir" "$test_dir/opensbi_fault_test.c" -o "$build/test"
    "$build/test"
done
