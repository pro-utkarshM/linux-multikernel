#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# Source must be a fresh pinned worktree with only the accompanying test patch.
set -euo pipefail
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
source_dir=${1:?OPEN_SBI_SOURCE KERNEL_BUILD MODE OUTPUT_PARENT}
kernel_build=${2:?missing kernel build}
mode=${3:?missing mode}
parent=${4:?missing output parent}
[[ "$mode" =~ ^[0-7]$ ]] || exit 2
test "$(git -C "$source_dir" rev-parse HEAD)" = 74434f255873d74e56cc50aa762d1caf24c099f8
cmp "$source_dir/lib/sbi/opensbi_test_hsm.h" "$test_dir/opensbi_test_hsm.h"
cmp <(git -C "$source_dir" -c diff.noprefix=false -c diff.mnemonicprefix=false diff -- lib/sbi/sbi_ecall_hsm.c) \
    "$test_dir/opensbi_test_hsm.patch"
test "$(git -C "$source_dir" status --porcelain)" = $' M lib/sbi/sbi_ecall_hsm.c\n?? lib/sbi/opensbi_test_hsm.h'
start=$(llvm-nm "$kernel_build/vmlinux.unstripped" | awk '$3 == "_start" {print $1}')
prime=$(llvm-nm "$kernel_build/vmlinux.unstripped" | awk '$3 == "mk_riscv_entry_fence_stop" {print $1}')
test -n "$start" && test -n "$prime"
offset=$(od -An -j8 -N8 -t u8 "$kernel_build/arch/riscv/boot/Image")
test "$((offset))" = 2097152
# QEMU virt DRAM base + frozen Image text_offset + exact ELF symbol delta.
printf -v physical '0x%x' "$((0x80000000 + offset + 16#$prime - 16#$start))"
case "$parent" in */build) ;; *) exit 2 ;; esac
mkdir -p "$parent"
bundle=$(mktemp -d "$parent/modern-firmware.XXXXXX")
printf 'Firmware bundle: %s mode=%s prime=%s\n' "$bundle" "$mode" "$physical"
install -m 0644 "$test_dir/opensbi_test_hsm.h" "$bundle/test-selector.h"
install -m 0644 "$test_dir/opensbi_test_hsm.patch" "$bundle/test-selector.patch"
printf '%s\n' 74434f255873d74e56cc50aa762d1caf24c099f8 > "$bundle/source-revision.txt"
printf 'mode=%s\nprime=%s\n' "$mode" "$physical" > "$bundle/selector.txt"
sha256sum "$kernel_build/arch/riscv/boot/Image" "$kernel_build/vmlinux.unstripped" > "$bundle/host-SHA256SUMS"
command=(make -C "$source_dir" PLATFORM=generic LLVM=1 O="$bundle/out" -j2
    "platform-cflags-y=-DMK_TEST_FAULT=$mode -DMK_TEST_PRIME=$physical")
printf '%q ' "${command[@]}" > "$bundle/build-command.txt"
printf '\n' >> "$bundle/build-command.txt"
"${command[@]}" > "$bundle/build.log" 2>&1
install -m 0644 "$bundle/out/platform/generic/firmware/fw_dynamic.bin" "$bundle/fw_dynamic.bin"
(cd "$bundle" && sha256sum fw_dynamic.bin test-selector.h test-selector.patch selector.txt > SHA256SUMS)
