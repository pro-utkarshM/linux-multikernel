#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# Extension of pinned #35 staging/packing; never modifies its checkout.
set -euo pipefail
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
kernel_build=${1:?KERNEL_BUILD HARNESS KERF_SOURCE RISCV_RUNTIME FIRMWARE OUTPUT_PARENT [MODE HARTS CYCLES]}
harness=${2:?missing harness}
kerf=${3:?missing Kerf source}
runtime=${4:?missing RISC-V runtime}
firmware=${5:?missing OpenSBI}
parent=${6:?missing output parent}
mode=${7:-graceful}
harts=${8:-1}
cycles=${9:-1}
case "$mode" in graceful|halt|poweroff|reboot|panic) ;; *) exit 2 ;; esac
case "$harts" in 1|2) ;; *) exit 2 ;; esac
[[ "$cycles" =~ ^[1-9][0-9]?$ ]] && (( cycles <= 50 )) || exit 2
test "$(git -C "$harness" rev-parse HEAD)" = 48507f176520b11a655344510b1b865b037e527f
test "$(git -C "$kerf" rev-parse HEAD)" = 38daa5687d6748846ffd003599a3bfba29785cd6
test -z "$(git -C "$harness" status --porcelain)"
test -z "$(git -C "$kerf" status --porcelain)"
diff -qr --exclude=__pycache__ "$kerf/src/kerf" "$runtime/usr/lib/python3/dist-packages/kerf"
for option in MULTIKERNEL MKTTY KPROBES; do
    grep -qx "CONFIG_$option=y" "$kernel_build/.config"
done
source_dir=$(readlink -f "$kernel_build/source")
test -z "$(git -C "$source_dir" status --porcelain)"
revision=$(git -C "$source_dir" rev-parse HEAD)
case "$parent" in */build) ;; *) echo 'output parent must end in /build' >&2; exit 2 ;; esac
mkdir -p "$parent"
bundle=$(mktemp -d "$parent/modern-lifecycle.XXXXXX")
printf 'Evidence bundle: %s\n' "$bundle"
install -m 0644 "$kernel_build/arch/riscv/boot/Image" "$bundle/Image"
install -m 0644 "$kernel_build/vmlinux.unstripped" "$bundle/vmlinux.unstripped"
install -m 0644 "$kernel_build/.config" "$bundle/kernel.config"
install -m 0644 "$firmware" "$bundle/fw_dynamic.bin"
install -m 0755 "$test_dir/qemu-host-init.py" "$bundle/guest-host.py"
install -m 0755 "$test_dir/qemu-child-init" "$bundle/guest-child"
printf '%s\n' "$revision" > "$bundle/kernel-revision.txt"
# Avoid merging /bin symlinks over the original harness's BusyBox directory.
mkdir "$bundle/runtime-view"
cp -a "$runtime/usr" "$runtime/lib" "$bundle/runtime-view/"
bash "$harness/scripts/build-initramfs.sh" secondary "$bundle/secondary-initrd.cpio.gz" \
    "$runtime/usr/bin/busybox" "$bundle/guest-child"
bash "$harness/scripts/build-initramfs.sh" host "$bundle/host-initrd.cpio.gz" \
    "$runtime/usr/bin/busybox" "$bundle/guest-host.py" "$bundle/runtime-view" \
    "$bundle/Image" "$bundle/secondary-initrd.cpio.gz" "$harness/initramfs/baseline-riscv.dts"
(
    cd "$bundle"
    sha256sum Image vmlinux.unstripped kernel.config fw_dynamic.bin guest-host.py guest-child \
        host-initrd.cpio.gz secondary-initrd.cpio.gz > SHA256SUMS
)
command=(qemu-system-riscv64 -machine virt -cpu rv64 -smp 4 -m 2048 -nographic \
    -monitor none -nic none -no-reboot -bios "$bundle/fw_dynamic.bin" \
    -kernel "$bundle/Image" -initrd "$bundle/host-initrd.cpio.gz" \
    -append "console=ttyS0,115200 rdinit=/init panic=0 kernelcore=1G log_buf_len=4M mk_lifecycle_guard=modern-v5 mk_lifecycle_mode=$mode mk_lifecycle_harts=$harts mk_lifecycle_cycles=$cycles")
printf '%q ' "${command[@]}" > "$bundle/command.txt"
printf '\n' >> "$bundle/command.txt"
rc=0
timeout --kill-after=5s "$((300 + cycles * 60))s" "${command[@]}" > "$bundle/serial.log" 2>&1 || rc=$?
printf '%s\n' "$rc" > "$bundle/exit-status.txt"
tail -30 "$bundle/serial.log"
python3 "$test_dir/verify_lifecycle.py" "$bundle/serial.log" "$rc" "$mode" "$harts" "$cycles"
