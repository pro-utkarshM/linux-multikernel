#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# Isolated whole-machine kexec, not a multikernel spawn lifecycle test.
set -euo pipefail
export GIT_OPTIONAL_LOCKS=0
if [[ $# != 7 && $# != 9 ]]; then
    echo 'usage: KERNEL_BUILD HARNESS KERF_SOURCE RISCV_RUNTIME FIRMWARE OUTPUT_PARENT MODE [EXPECTED_SOURCE EXPECTED_REVISION]' >&2
    exit 2
fi
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
kernel_build=${1:?KERNEL_BUILD HARNESS KERF_SOURCE RISCV_RUNTIME FIRMWARE OUTPUT_PARENT MODE}
harness=${2:?missing harness}
kerf=${3:?missing Kerf source}
runtime=${4:?missing RISC-V runtime}
firmware=${5:?missing OpenSBI firmware}
parent=${6:?missing output parent}
mode=${7:?missing ordinary or crash mode}
case "$mode" in
    ordinary|crash) ;;
    *) echo 'mode must be ordinary or crash' >&2; exit 2 ;;
esac
kernel_build=$(readlink -f "$kernel_build")
harness=$(readlink -f "$harness")
kerf=$(readlink -f "$kerf")
runtime=$(readlink -f "$runtime")
firmware=$(readlink -f "$firmware")
recipe_source=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
tree_status=$(git -C "$recipe_source" status --porcelain)
test -z "$tree_status"
recipe_revision=$(git -C "$recipe_source" rev-parse HEAD)
expected_source=$recipe_source
expected_revision=$recipe_revision
if [[ $# == 9 ]]; then
    if [[ -z "$8" || ! "$9" =~ ^[0-9a-f]{40}$ ]]; then
        echo 'override requires a source directory and full commit SHA' >&2
        exit 2
    fi
    expected_source=$(readlink -e "$8")
    expected_revision=$9
fi
source_dir=$(readlink -e "$kernel_build/source")
test "$source_dir" = "$expected_source"
tree_status=$(git -C "$source_dir" status --porcelain)
test -z "$tree_status"
revision=$(git -C "$source_dir" rev-parse HEAD)
test "$revision" = "$expected_revision"
test "$(cat "$kernel_build/source-revision.txt")" = "$revision"
repo=$(readlink -f "$(git -C "$source_dir" rev-parse --git-common-dir)/..")
test "$(git -C "$harness" rev-parse HEAD)" = 48507f176520b11a655344510b1b865b037e527f
test "$(git -C "$kerf" rev-parse HEAD)" = 38daa5687d6748846ffd003599a3bfba29785cd6
tree_status=$(git -C "$harness" status --porcelain)
test -z "$tree_status"
tree_status=$(git -C "$kerf" status --porcelain)
test -z "$tree_status"
diff -qr --exclude=__pycache__ "$kerf/src/kerf" "$runtime/usr/lib/python3/dist-packages/kerf"
for option in RISCV 64BIT KEXEC KEXEC_FILE CRASH_RESERVE CRASH_DUMP PROC_VMCORE MAGIC_SYSRQ; do
    grep -qx "CONFIG_$option=y" "$kernel_build/.config"
done
case "$parent" in */build) ;; *) echo 'output parent must end in /build' >&2; exit 2 ;; esac
mkdir -p "$parent"
bundle=$(mktemp -d "$parent/ordinary-kexec.XXXXXX")
bundle=$(readlink -f "$bundle")
printf 'Evidence bundle: %s\n' "$bundle"
install -m 0644 "$kernel_build/arch/riscv/boot/Image" "$bundle/Image"
install -m 0644 "$kernel_build/vmlinux.unstripped" "$bundle/vmlinux.unstripped"
install -m 0644 "$kernel_build/.config" "$bundle/kernel.config"
install -m 0644 "$firmware" "$bundle/fw_dynamic.bin"
install -m 0755 "$test_dir/qemu_kexec_guest.py" "$bundle/guest-primary.py"
install -m 0755 "$test_dir/qemu-kexec-target" "$bundle/guest-target"
install -m 0644 "$test_dir/verify_kexec.py" "$bundle/verify_kexec.py"
install -m 0644 "$test_dir/qemu_kexec_test.sh" "$bundle/qemu_kexec_test.sh"
install -m 0644 "$kernel_build/include/config/kernel.release" "$bundle/kernel.release"
install -m 0644 "$kernel_build/build-artifacts.sha256" "$bundle/build-artifacts.sha256"
python3 "$bundle/verify_kexec.py" --artifacts "$repo" "$kernel_build" "$bundle" \
    > "$bundle/artifact-verification.json"
printf '%s\n' "$revision" > "$bundle/source-revision.txt"
printf '%s\n' "$source_dir" > "$bundle/source-path.txt"
printf '%s\n' "$recipe_revision" > "$bundle/recipe-revision.txt"
printf '%s\n' "$recipe_source" > "$bundle/recipe-source-path.txt"
python3 -c 'import secrets; print(secrets.token_hex(16))' > "$bundle/token.txt"
token=$(cat "$bundle/token.txt")
image_sha=$(sha256sum "$bundle/Image" | cut -d ' ' -f 1)
mkdir "$bundle/runtime-view"
cp -a "$runtime/usr" "$runtime/lib" "$bundle/runtime-view/"
mkdir "$bundle/runtime-view/payload"
install -m 0644 "$bundle/kernel.release" "$bundle/runtime-view/payload/vmlinux.release"
printf '%s\n' "$image_sha" > "$bundle/runtime-view/payload/vmlinux.sha256"
bash "$harness/scripts/build-initramfs.sh" secondary "$bundle/target-initrd.cpio.gz" \
    "$runtime/usr/bin/busybox" "$bundle/guest-target"
bash "$harness/scripts/build-initramfs.sh" host "$bundle/primary-initrd.cpio.gz" \
    "$runtime/usr/bin/busybox" "$bundle/guest-primary.py" "$bundle/runtime-view" \
    "$bundle/Image" "$bundle/target-initrd.cpio.gz" "$harness/initramfs/baseline-riscv.dts"
qemu-system-riscv64 --version > "$bundle/qemu-version.txt"
printf '%s\n' 48507f176520b11a655344510b1b865b037e527f > "$bundle/harness-revision.txt"
printf '%s\n' 38daa5687d6748846ffd003599a3bfba29785cd6 > "$bundle/kerf-revision.txt"
cmdline="console=ttyS0,115200 rdinit=/init panic=0 loglevel=7"
cmdline+=" mk_kexec_guard=vm-v1 mk_kexec_stage=primary mk_kexec_mode=$mode mk_kexec_token=$token"
if [[ "$mode" == crash ]]; then
    cmdline+=' crashkernel=256M'
fi
command=(qemu-system-riscv64 -machine virt -cpu rv64 -smp 4 -m 2048 -nographic \
    -monitor none -nic none -no-reboot -bios "$bundle/fw_dynamic.bin" \
    -kernel "$bundle/Image" -initrd "$bundle/primary-initrd.cpio.gz" -append "$cmdline")
printf '%q ' "${command[@]}" > "$bundle/command.txt"
printf '\n' >> "$bundle/command.txt"
(
    cd "$bundle"
    sha256sum Image vmlinux.unstripped kernel.config fw_dynamic.bin kernel.release \
        guest-primary.py guest-target verify_kexec.py primary-initrd.cpio.gz \
        target-initrd.cpio.gz source-revision.txt token.txt command.txt qemu-version.txt \
        harness-revision.txt kerf-revision.txt build-artifacts.sha256 \
        artifact-verification.json qemu_kexec_test.sh source-path.txt \
        recipe-revision.txt recipe-source-path.txt > SHA256SUMS
)
rc=0
timeout --kill-after=5s 300s "${command[@]}" > "$bundle/serial.log" 2>&1 || rc=$?
printf '%s\n' "$rc" > "$bundle/exit-status.txt"
tail -30 "$bundle/serial.log"
verify_status=0
python3 "$bundle/verify_kexec.py" "$bundle/serial.log" "$rc" "$mode" "$token" \
    "$(cat "$bundle/kernel.release")" "$image_sha" > "$bundle/verification.json" \
    2> "$bundle/verification.stderr" || verify_status=$?
printf '%s\n' "$verify_status" > "$bundle/verifier-exit-status.txt"
cat "$bundle/verification.json" "$bundle/verification.stderr"
(
    cd "$bundle"
    sha256sum serial.log exit-status.txt verification.json verification.stderr \
        verifier-exit-status.txt >> SHA256SUMS
)
exit "$verify_status"
