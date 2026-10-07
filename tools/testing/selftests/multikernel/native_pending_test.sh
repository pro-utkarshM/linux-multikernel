#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-native-pending.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^struct mk_pending_msg \{/ {copy=1}
     /^static (LIST_HEAD|DEFINE_RAW_SPINLOCK)\(mk_pending_msgs/ {print}
     /^static u64 mk_last_msg_id;/ {print}
     /^(struct mk_pending_msg \*|void |int |u64 )mk_msg_pending_/ {copy=1}
     copy {print}
     copy && /^}/ {copy=0}' "$src/kernel/multikernel/messaging.c" > "$build/pending.h"
${CC:-cc} ${CFLAGS:-} -DMK_NATIVE_TEST_KERNEL -std=gnu11 -Wall -Wextra -Werror \
    -Wno-unused-function -Wno-unused-variable -I"$build" -I"$test_dir" \
    -I"$src/tools/include" "$test_dir/native_pending_test.c" -o "$build/test"
"$build/test"
