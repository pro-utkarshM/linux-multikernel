# SPDX-License-Identifier: GPL-2.0-only
"""Private corrected-kernel VM observation using existing tracefs interfaces."""
import ctypes
import errno
import os
from pathlib import Path
import platform
from verify_cmdline import verify_record


def run(trace_root, payload, host_boot, status, register_probe, marker):
    if os.getpid() != 1 or platform.machine() != 'riscv64':
        raise RuntimeError('command-line test requires disposable RISC-V guest PID1')
    if 'no_hash_pointers' not in Path('/proc/cmdline').read_text().split():
        raise RuntimeError('allocator pointer correlation requires explicit VM-only no_hash_pointers')
    from kerf.architecture import get_kexec_file_load_syscall
    from kerf.load.main import kexec_file_load, KEXEC_MULTIKERNEL, KEXEC_MK_ID
    from kerf.unload.main import kexec_file_unload, KEXEC_FILE_UNLOAD
    base = Path('/sys/fs/multikernel')
    ownership = {path: (base / path).read_bytes() for path in
                 ('device_tree', 'instances/lifecycle-test/device_tree')}
    flags = KEXEC_MULTIKERNEL | KEXEC_MK_ID(1)
    # Isolate allocator evidence from the existing HSM/copy/start trace windows.
    trace = trace_root / 'instances/mk_cmdline'
    trace.mkdir()
    (trace / 'tracing_on').write_text('0')
    (trace / 'buffer_size_kb').write_text('2048')
    (trace / 'trace_clock').write_text('global')
    register_probe(trace_root, 'r:mk_cmdline_alloc memdup_user ptr=$retval:x64 length=$arg2:u64')
    events = dict(alloc='kprobes/mk_cmdline_alloc', kmalloc='kmem/kmalloc', kfree='kmem/kfree')
    for event in events.values():
        (trace / 'events' / event / 'filter').write_text('common_pid == 1')
        (trace / 'events' / event / 'enable').write_text('1')

    for phase in ('rejected', 'control'):
        control = phase == 'control'
        command = 'rdinit=/init console=mktty0 panic=1 mk_lifecycle_child=1 mk_cmdline_control=1'
        length = len(command.encode()) + int(control)
        loaded_state = loaded_kimage = None
        def mark(kind):
            (trace / 'trace_marker').write_text(f'MK_CMDLINE_{kind} {phase} {host_boot}\n')
        (trace / 'trace').write_text('\n')
        (trace / 'tracing_on').write_text('1')
        try:
            mark('BEGIN')
            with payload.open('rb') as kernel, open('/payload/secondary-initrd.cpio.gz', 'rb') as initrd:
                if control:
                    kexec_file_load(kernel.fileno(), initrd.fileno(), command, flags)
                    error = 0
                    loaded_state = status()
                    loaded_kimage = Path('/proc/kimage').read_text()
                    mark('LOADED')
                    mark('UNLOAD')
                    kexec_file_unload(flags | KEXEC_FILE_UNLOAD)
                else:
                    # Ordinary argument validation: valid Image/initrd, but the
                    # submitted length excludes the command line's final NUL.
                    libc = ctypes.CDLL(None, use_errno=True)
                    libc.syscall.restype = ctypes.c_long
                    libc.syscall.argtypes = [ctypes.c_long, ctypes.c_int, ctypes.c_int,
                                             ctypes.c_ulong, ctypes.c_char_p, ctypes.c_ulong]
                    result = libc.syscall(get_kexec_file_load_syscall(), kernel.fileno(),
                                          initrd.fileno(), length, command.encode(), flags)
                    error = ctypes.get_errno()
                    if result != -1 or error != errno.EINVAL:
                        raise RuntimeError('expected ordinary post-allocation EINVAL')
            mark('END')
        finally:
            (trace / 'tracing_on').write_text('0')
        with (trace / 'trace').open() as stream:
            evidence = stream.read(8 * 1024 * 1024 + 1)
        if len(evidence) > 8 * 1024 * 1024:
            raise RuntimeError('allocator evidence exceeds bounded output')
        health = dict(enabled={'tracing_on': (trace / 'tracing_on').read_text().strip()},
                      filters={}, profile=(trace_root / 'kprobe_profile').read_text(),
                      stats={path.parent.name: path.read_text()
                             for path in (trace / 'per_cpu').glob('cpu*/stats')})
        for name, event in events.items():
            health['enabled'][name] = (trace / 'events' / event / 'enable').read_text().strip()
            health['filters'][name] = (trace / 'events' / event / 'filter').read_text().strip()
        row = dict(phase=phase, host_boot=host_boot, command=command, length=length, error=error,
                   state=status(), kimage=Path('/proc/kimage').read_text(),
                   loaded_state=loaded_state, loaded_kimage=loaded_kimage, trace=evidence, health=health,
                   ownership_unchanged=all((base / path).read_bytes() == data for path, data in ownership.items()))
        verify_record(row)
        marker('CMDLINE', **row)
    # No allocator tracing during the following independent lifecycle recovery.
    for event in events.values():
        (trace / 'events' / event / 'enable').write_text('0')
