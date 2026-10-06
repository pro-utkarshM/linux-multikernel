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
alternate_build=${10:-}
images=same
test -z "$alternate_build" || images=alternate
fault=${11:-0}
case "$mode" in
    graceful|halt|poweroff|reboot|panic|deny-primary|partial-start|stuck-stop|\
    loader-negative|failed-retain|lost-ack|writer-stress|manifest-prepare|\
    manifest-capacity|placement-negative) ;;
    *) exit 2 ;;
esac
[[ "$fault" =~ ^[0-8]$ ]] || exit 2
case "$harts" in 1|2) ;; *) exit 2 ;; esac
[[ "$cycles" =~ ^[1-9][0-9]?$ ]] && (( cycles <= 50 )) || exit 2
manifest_fault=0
case "$mode" in
    manifest-prepare) manifest_fault=1 ;;
    manifest-capacity) manifest_fault=2 ;;
esac
if (( manifest_fault )) || [[ "$mode" == placement-negative ]]; then
    (( cycles == 1 && fault == 0 )) && test -z "$alternate_build" || exit 2
fi
placement_arg=
if [[ "$mode" == placement-negative ]]; then
    placement_arg=' mk_test_bad_placement=1'
fi
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
install -m 0644 "$test_dir/verify_lifecycle.py" "$bundle/verify_lifecycle.py"
install -m 0644 "$test_dir/verify_fault.py" "$bundle/verify_fault.py"
install -m 0644 "$test_dir/verify_pending.py" "$bundle/verify_pending.py"
install -m 0644 "$test_dir/verify_loader.py" "$bundle/verify_loader.py"
install -m 0644 "$test_dir/verify_manifest.py" "$bundle/verify_manifest.py"
install -m 0644 "$test_dir/verify_placement.py" "$bundle/verify_placement.py"
install -m 0644 "$test_dir/verify_retention.py" "$bundle/verify_retention.py"
printf '%s\n' "$revision" > "$bundle/kernel-revision.txt"
# Avoid merging /bin symlinks over the original harness's BusyBox directory.
mkdir "$bundle/runtime-view"
cp -a "$runtime/usr" "$runtime/lib" "$bundle/runtime-view/"
mkdir "$bundle/runtime-view/payload"
install -m 0644 "$bundle/verify_retention.py" "$bundle/runtime-view/payload/verify_retention.py"
install -m 0644 "$kernel_build/include/config/kernel.release" "$bundle/runtime-view/payload/vmlinux.release"
if test -n "$alternate_build"; then
    (( cycles >= 2 ))
    test "$(readlink -f "$alternate_build/source")" = "$source_dir"
    cmp "$kernel_build/.config" "$alternate_build/.config"
    ! cmp -s "$kernel_build/arch/riscv/boot/Image" "$alternate_build/arch/riscv/boot/Image"
    ! cmp -s "$kernel_build/include/config/kernel.release" "$alternate_build/include/config/kernel.release"
    install -m 0644 "$alternate_build/arch/riscv/boot/Image" "$bundle/Image-alt"
    install -m 0644 "$alternate_build/vmlinux.unstripped" "$bundle/vmlinux-alt.unstripped"
    install -m 0644 "$alternate_build/arch/riscv/boot/Image" "$bundle/runtime-view/payload/vmlinux-alt"
    install -m 0644 "$alternate_build/include/config/kernel.release" "$bundle/runtime-view/payload/vmlinux-alt.release"
fi
qemu-system-riscv64 --version > "$bundle/qemu-version.txt"
clang --version > "$bundle/clang-version.txt"
printf '%s\n' 48507f176520b11a655344510b1b865b037e527f > "$bundle/harness-revision.txt"
printf '%s\n' 38daa5687d6748846ffd003599a3bfba29785cd6 > "$bundle/kerf-revision.txt"
bash "$harness/scripts/build-initramfs.sh" secondary "$bundle/secondary-initrd.cpio.gz" \
    "$runtime/usr/bin/busybox" "$bundle/guest-child"
bash "$harness/scripts/build-initramfs.sh" host "$bundle/host-initrd.cpio.gz" \
    "$runtime/usr/bin/busybox" "$bundle/guest-host.py" "$bundle/runtime-view" \
    "$bundle/Image" "$bundle/secondary-initrd.cpio.gz" "$harness/initramfs/baseline-riscv.dts"
(
    cd "$bundle"
    sha256sum Image vmlinux.unstripped kernel.config fw_dynamic.bin guest-host.py guest-child \
        host-initrd.cpio.gz secondary-initrd.cpio.gz verify_lifecycle.py verify_fault.py \
        verify_pending.py verify_loader.py verify_manifest.py verify_placement.py \
        verify_retention.py \
        qemu-version.txt clang-version.txt harness-revision.txt kerf-revision.txt > SHA256SUMS
    if test -n "$alternate_build"; then
        sha256sum Image-alt vmlinux-alt.unstripped >> SHA256SUMS
    fi
)
cmdline="console=ttyS0,115200 rdinit=/init panic=0 kernelcore=1G log_buf_len=4M"
cmdline+=" mk_test_resource_trace=1 mk_test_manifest_fault=$manifest_fault$placement_arg"
cmdline+=" mk_test_drop_shutdown_ack=$([[ $mode == lost-ack ]] && echo 1 || echo 0)"
cmdline+=" mk_lifecycle_guard=modern-v5 mk_lifecycle_mode=$mode mk_lifecycle_harts=$harts"
cmdline+=" mk_lifecycle_cycles=$cycles mk_lifecycle_images=$images mk_lifecycle_fault=$fault"
command=(qemu-system-riscv64 -machine virt -cpu rv64 -smp 4 -m 2048 -nographic \
    -monitor none -nic none -no-reboot -bios "$bundle/fw_dynamic.bin" \
    -kernel "$bundle/Image" -initrd "$bundle/host-initrd.cpio.gz" \
    -append "$cmdline")
printf '%q ' "${command[@]}" > "$bundle/command.txt"
printf '\n' >> "$bundle/command.txt"
rc=0
timeout --kill-after=5s "$((300 + cycles * 60))s" "${command[@]}" > "$bundle/serial.log" 2>&1 || rc=$?
printf '%s\n' "$rc" > "$bundle/exit-status.txt"
tail -30 "$bundle/serial.log"
case "$mode" in
    failed-retain|lost-ack)
        python3 "$bundle/verify_retention.py" "$bundle/serial.log" "$rc" "$mode" "$fault" ;;
    loader-negative)
        python3 "$bundle/verify_loader.py" "$bundle/serial.log" "$rc" "$harts" ;;
    manifest-prepare|manifest-capacity)
        python3 "$bundle/verify_manifest.py" "$bundle/serial.log" "$rc" "$mode" "$harts" ;;
    placement-negative)
        python3 "$bundle/verify_placement.py" "$bundle/serial.log" "$rc" "$harts" ;;
    deny-primary|partial-start|stuck-stop)
        python3 "$bundle/verify_fault.py" "$bundle/serial.log" "$rc" "$mode" "$fault" ;;
    *) python3 "$bundle/verify_lifecycle.py" "$bundle/serial.log" "$rc" "$mode" "$harts" "$cycles" "$images" ;;
esac
if test "$fault" = 6; then
    python3 "$bundle/verify_pending.py" "$bundle/serial.log" "$rc"
fi
