# kbox

kbox boots a real Linux kernel as an in-process library ([LKL](https://github.com/lkl/linux)) and routes intercepted syscalls to it. Three interception tiers are available: seccomp-unotify (most compatible), SIGSYS trap (lower latency), and binary rewriting (near-native for process-info syscalls). The default `auto` mode selects the fastest tier that works for a given workload. kbox provides a rootless chroot/proot alternative with kernel-level syscall accuracy.

## Why kbox

Running Linux userspace programs in a rootless, unprivileged environment requires intercepting their syscalls and providing a convincing kernel interface. Existing tools fall short:

- `chroot` requires root privileges (or user namespaces, which are unavailable on many systems including Termux and locked-down shared hosts).
- `proot` uses ptrace for syscall interception. ptrace is slow (two context switches per syscall), cannot faithfully emulate all syscalls, breaks under complex multi-threaded workloads, and its path translation is vulnerable to TOCTOU races.
- User Mode Linux (UML) runs as a separate supervisor/guest process tree with ptrace-based syscall routing, imposing overhead and complexity that LKL avoids by running in-process.
- `gVisor` implements a userspace kernel from scratch -- millions of lines reimplementing Linux semantics, inevitably diverging from the real kernel on edge cases.

kbox takes a fundamentally different approach: boot the actual Linux kernel as an in-process library and route intercepted syscalls to it. The kernel that handles your `open()` is the same kernel that runs on servers in production. No reimplementation, no approximation.

The interception mechanism matters too. kbox offers three tiers, each trading isolation for speed:

- **Seccomp-unotify** (Tier 3): syscall notifications delivered to a separate supervisor process via `SECCOMP_RET_USER_NOTIF`. Strongest isolation, lowest overhead for file I/O. The supervisor dispatches to LKL and injects results back via two ioctl round-trips per syscall.
- **SIGSYS trap** (Tier 1): in-process signal handler intercepts syscalls via `SECCOMP_RET_TRAP`. No cross-process round-trip, but the signal frame build/restore and a service-thread hand-off (eventfd + futex) add overhead. Best for metadata operations on aarch64 where the USER_NOTIF round-trip cost is proportionally higher.
- **Binary rewriting** (Tier 2): syscall instructions patched to call a trampoline at load time. On aarch64, `SVC #0` is replaced with a `B` branch into a per-site trampoline that calls the dispatch function directly on the guest thread, with zero signal overhead, zero context switches, and zero FS base switching. Stat from the LKL inode cache completes in-process without any kernel round-trip. On x86_64, only 8-byte wrapper sites (`mov $NR; syscall; ret`) are patched; bare 2-byte `syscall` instructions cannot currently be rewritten in-place (the only same-width replacement, `call *%rax`, would jump to the syscall number in RAX), so unpatched sites fall through to the SIGSYS trap path. Process-info syscalls (getpid, gettid) at wrapper sites return virtualized values inline at native speed.

The default `--syscall-mode=auto` selects the fastest tier for each command. Non-shell direct binaries use rewrite/trap on both x86_64 and aarch64 (faster open+close and lseek+read via the local fast-path that bypasses the service thread for 50+ LKL-free syscalls). Shell invocations and networking commands use seccomp (fork/exec coherence and SLIRP poll loop require the supervisor). The selection is based on binary analysis: the main executable is scanned for fork/clone wrapper sites, and binaries that can fork fall back to seccomp. A guest-thread local fast-path (`kbox_dispatch_try_local_fast_path`) handles brk, futex, epoll, poll, mmap, munmap, and other host-kernel operations with zero IPC overhead. An FD-local stat cache avoids repeated LKL inode lookups for fstat on the same file descriptor. (Note: ASAN builds pin AUTO to seccomp; the trap path's guest-stack switch is incompatible with sanitizer memory tracking.)

The result: programs get real VFS, real ext4, real procfs, at near-native syscall speed, without root privileges, containers, VMs, or ptrace.

## How it works

```
     Seccomp mode (--syscall-mode=seccomp, shell commands in auto)

                 ┌────────────────┐
                 │  guest child   │  (seccomp BPF: USER_NOTIF)
                 └──────┬─────────┘
                        │ syscall notification
                 ┌──────▼──────────┐          ┌──────────────────┐
                 │  supervisor     │────────▶ │  web observatory │
                 │  (dispatch)     │ counters │  (HTTP + SSE)    │
                 └────┬───────┬────┘ events   └────────┬─────────┘
          LKL path    │       │  host path             │
          ┌───────────▼──┐ ┌──▼──────────┐             ▼
          │  LKL kernel  │ │ host kernel │     ┌──────────────┐
          │  (in-proc)   │ │             │     │  web browser │
          └──────────────┘ └─────────────┘     └──────────────┘

     Trap mode (--syscall-mode=trap, direct binaries in auto)

                 ┌─────────────────────────────────────────┐
                 │            single process               │
                 │  ┌─────────────┐   ┌──────────────────┐ │
                 │  │ guest code  │──▶│ SIGSYS handler   │ │
                 │  │ (loaded ELF)│   │ (dispatch thread)│ │
                 │  └─────────────┘   └───┬────────┬─────┘ │
                 │              LKL path  │        │ host  │
                 │          ┌─────────────▼──┐ ┌───▼─────┐ │
                 │          │  LKL kernel    │ │ host    │ │
                 │          │  (in-proc)     │ │ kernel  │ │
                 │          └────────────────┘ └─────────┘ │
                 └─────────────────────────────────────────┘
```

1. The supervisor opens a rootfs disk image and registers it as an LKL block device.
2. LKL boots a real Linux kernel inside the process (no VM, no separate process tree).
3. The filesystem is mounted via LKL, and the supervisor sets the guest's virtual root via LKL's internal chroot.
4. The launch path depends on the syscall mode:
   - **Seccomp**: a child process is forked with a BPF filter that delivers syscalls as user notifications. The supervisor receives each notification, dispatches to LKL or the host kernel, and injects results back.
   - **Trap**: the guest binary is loaded into the current process via a userspace ELF loader. A BPF filter traps guest-range syscalls via `SECCOMP_RET_TRAP`, delivering SIGSYS. A service thread runs the dispatch; the signal handler captures the request and spins until the result is ready. No cross-process round-trip.
   - **Rewrite**: same as trap, but additionally patches syscall instructions to branch directly into dispatch trampolines, eliminating the SIGSYS signal overhead entirely for patched sites. On **aarch64**, `SVC #0` (4 bytes, fixed-width) is replaced with a `B` branch to a per-site trampoline past the segment end; veneer pages with `LDR+BR` indirect stubs bridge sites beyond ±128MB. The trampoline saves registers, calls the C dispatch function on the guest thread, and returns. No signal frame, no service thread, no context switch. On **x86_64**, only 8-byte wrapper sites (`mov $NR, %eax; syscall; ret`) can be safely patched (to `jmp rel32` targeting a wrapper trampoline); bare 2-byte `syscall`/`sysenter` instructions cannot be rewritten in-place because the replacement `call *%rax` would jump to the syscall number, not a code address. Unpatched x86_64 sites fall through to the SIGSYS trap path. An instruction-boundary-aware length decoder (`x86-decode.c`) ensures the scanner never matches `0F 05` bytes that appear inside longer instructions (immediates, displacements). Site-aware classification labels each site as WRAPPER (eligible for inline virtualized getpid=1, gettid=1) or COMPLEX (must use full dispatch). W^X enforcement blocks simultaneous `PROT_WRITE|PROT_EXEC` in guest memory.
   - **Auto** (default): selects the fastest tier per command. Non-shell direct binaries whose main executable has no fork/clone wrapper sites use rewrite/trap on both x86_64 and aarch64. On aarch64, rewrite delivers ~7x faster stat (~3us vs 22us seccomp) via in-process LKL inode cache. On x86_64, trap delivers faster lseek+read (~1.4x) and open+close (~1.1x) via the guest-thread local fast-path (50+ CONTINUE syscalls bypass the service thread entirely). Shell invocations and `--net` commands always use seccomp (fork coherence and SLIRP poll loop). If the selected tier fails at install time, auto falls through to the next tier. ASAN builds pin auto to seccomp (guest-stack switch incompatible with sanitizer tracking).

### Syscall routing

Every intercepted syscall is dispatched to one of three dispositions:

- **LKL forward** (~74 handlers): filesystem operations (open, read, write, stat, getdents, mkdir, unlink, rename), metadata (chmod, chown, utimensat), identity (getuid, setuid, getgroups), and networking (socket, connect). In seccomp mode, the supervisor reads arguments from tracee memory via `process_vm_readv` and writes results via `process_vm_writev`. In trap/rewrite mode, guest memory is accessed directly via `memcpy` (same address space) with `sigsetjmp`-based fault recovery that returns `-EFAULT` for unmapped pointers. An FD-local stat cache (16 entries, round-robin) avoids repeated LKL inode lookups for fstat.
- **Host CONTINUE** (~50 entries): scheduling (sched_yield, sched_setscheduler), signals (rt_sigaction, kill, tgkill), memory management (mmap, mprotect, brk, munmap, mremap), I/O multiplexing (epoll, poll, select), threading (futex, clone, set_tid_address, rseq), time (nanosleep, clock_gettime), and more. In seccomp mode, the kernel replays the syscall. In trap/rewrite mode, a guest-thread local fast-path (`kbox_dispatch_try_local_fast_path`) returns CONTINUE directly without touching the service thread -- zero IPC overhead for these high-frequency operations.
- **Emulated**: process identity (getpid returns 1, gettid returns 1), uname (synthetic LKL values), getrandom (LKL `/dev/urandom`), clock_gettime/gettimeofday (host clock, direct passthrough for latency).

All three tiers share the same dispatch engine (`kbox_dispatch_request`). The `kbox_syscall_request` abstraction decouples the dispatch logic from the notification transport: seccomp notifications, SIGSYS signal info, and rewrite trampoline calls all produce the same request struct.

Unknown syscalls receive `ENOSYS`. ~50 dangerous syscalls (mount, reboot, init_module, bpf, ptrace, etc.) are rejected with `EPERM` directly in the BPF filter before reaching the supervisor.

### Key subsystems

**Virtual FD table** (`fd_table.c`): maintains a mapping from guest FD numbers to LKL-internal FDs. Two ranges: low FDs (0..1023) populated only by dup2/dup3 for shell I/O redirection, high FDs (32768+) for normal allocation. This split avoids collisions between host-kernel FDs (pipes, inherited descriptors) and LKL-managed FDs.

**Shadow FDs** (`shadow_fd.c`): when the guest opens a regular file O_RDONLY, the supervisor copies its contents from LKL into a host-visible memfd. The tracee receives the memfd number, enabling native mmap without LKL involvement. This is essential for dynamic linking: the ELF loader maps `.text` and `.rodata` segments via mmap, which requires a real host FD. Shadow FDs are point-in-time snapshots (no write-back), capped at 256MB.

**Path translation** (`path.c`): lexical normalization with 6 escape-prevention checks. Paths starting with `/proc`, `/sys`, `/dev` are routed to the host kernel via CONTINUE. Everything else goes through LKL. The normalizer handles `..` traversal, double slashes, and symlink-based escape attempts (`/proc/self/root`, `/proc/<pid>/cwd`).

**ELF extraction** (`elf.c`, `image.c`): binaries are extracted from the LKL filesystem into memfds for `fexecve`. For dynamically-linked binaries, the PT_INTERP segment names an interpreter (e.g., `/lib/ld-musl-x86_64.so.1`) that does not exist on the host. The supervisor extracts the interpreter into a second memfd and patches PT_INTERP in the main binary to `/proc/self/fd/N`. The host kernel resolves this during `load_elf_binary`, before close-on-exec runs.

**Pipe architecture**: `pipe()`/`pipe2()` create real host pipes injected into the tracee via `SECCOMP_IOCTL_NOTIF_ADDFD`. No LKL involvement; the host kernel manages fork inheritance and close semantics natively. This is why shell pipelines work: both parent and child share real pipe FDs that the host kernel handles.

**Trap fast path** (`syscall-trap.c`, `loader-*.c`): for direct binary commands, kbox loads the guest ELF into the current process via a userspace loader (7 modules: entry, handoff, image, layout, launch, stack, transfer). A BPF filter traps guest-range instruction pointers via `SECCOMP_RET_TRAP`, delivering SIGSYS. The signal handler saves/restores the FS base (FSGSBASE instructions on kernel 5.9+, arch_prctl fallback) so kbox and guest each use their own TLS. A service thread runs the full dispatch; the handler captures the request and spins until the result is ready, keeping heap-allocating code out of signal context. `arch_prctl(SET_FS)` is intercepted to maintain dual TLS state.

**Rewrite engine** (`rewrite.c`, `x86-decode.c`): scans executable PT_LOAD segments for syscall instructions and patches them to branch directly into dispatch trampolines, eliminating the SIGSYS signal overhead for patched sites.

On **aarch64**, `SVC #0` (4 bytes, fixed-width) is replaced with a `B` branch to a per-site trampoline allocated past the segment end. The trampoline saves registers, loads the origin address, and calls the C dispatch function directly on the guest thread. No signal frame, no service thread context switch. Veneer pages with `LDR x16, [PC+8]; BR x16` indirect stubs bridge sites beyond the ±128MB `B`-instruction range, with slot reuse to avoid wasting a full page per veneer. This is why aarch64 rewrite achieves ~3us stat (vs 22us in seccomp): the dispatch runs in-process with LKL serving from the inode cache.

On **x86_64**, an instruction-boundary-aware length decoder (`x86-decode.c`) walks true instruction boundaries, eliminating false matches of `0F 05`/`0F 34` bytes inside immediates, displacements, and SIB encodings. Only 8-byte wrapper sites (`mov $NR, %eax; syscall; ret`) are patched to `jmp rel32` targeting a wrapper trampoline that encodes the syscall number and origin address. Bare 2-byte `syscall` instructions are not rewritten because the only same-width replacement (`call *%rax`, `FF D0`) would jump to the syscall number in RAX rather than a code address. Unpatched sites fall through to the SIGSYS trap path. However, the guest-thread local fast-path (`kbox_dispatch_try_local_fast_path`) handles 50+ high-frequency syscalls (futex, brk, epoll, poll, mmap, munmap, etc.) directly on the guest thread without any service-thread IPC, giving trap mode a measurable advantage over seccomp for operations surrounded by these host-kernel calls.

Each site is classified as WRAPPER (simple `syscall; ret` pattern, eligible for inline virtualized return: getpid=1, gettid=1, getppid=0) or COMPLEX (result consumed internally by helpers like `raise()` that feed gettid into tgkill; must use full dispatch). An origin map validates dispatch calls against known rewrite sites and carries the per-site classification. During re-exec (`trap_userspace_exec`), the rewrite runtime is re-installed on the new binary. Multi-threaded guests (`CLONE_THREAD`) are blocked in trap/rewrite mode; use `--syscall-mode=seccomp` for threaded workloads.

### ABI translation

LKL is built as `ARCH=lkl`, which uses asm-generic headers. On x86_64, `struct stat` differs between asm-generic (128 bytes, `st_mode` at offset 16) and the native layout (144 bytes, `st_mode` at offset 24). Reading `st_mode` from an LKL-filled buffer using a host `struct stat` reads `st_uid` instead. kbox uses `struct kbox_lkl_stat` matching the asm-generic layout, with field-by-field conversion via `kbox_lkl_stat_to_host()` before writing to tracee memory. Compile-time `_Static_assert` checks enforce struct sizes and critical field offsets.

seccomp `args[]` zero-extends 32-bit values: fd=-1 becomes `0x00000000FFFFFFFF`, not `0xFFFFFFFFFFFFFFFF`. All handlers extracting signed arguments (AT_FDCWD, MAP_ANONYMOUS fd) truncate to 32 bits before sign-extending: `(long)(int)(uint32_t)args[N]`.

On aarch64, four `O_*` flags differ between the host and asm-generic: `O_DIRECTORY`, `O_NOFOLLOW`, `O_DIRECT`, `O_LARGEFILE`. The dispatch layer translates these bidirectionally.

## Building

First, bootstrap with a default config.

```bash
make defconfig
```

Linux only (host kernel 5.0+ for seccomp-unotify, 5.9+ for FSGSBASE trap optimization). Requires GCC, GNU Make, and a pre-built `liblkl.a`. No `libseccomp` dependency; the BPF filter is compiled natively.

```bash
make                        # debug build (ASAN + UBSAN enabled)
make BUILD=release          # release build
make KBOX_HAS_WEB=1         # enable web-based kernel observatory
```

For cross-compilation, use `ARCH` to specify the target architecture and `CC` for the toolchain.

```bash
make BUILD=release ARCH=aarch64 CC=aarch64-linux-gnu-gcc
```

LKL is fetched automatically from the [nightly pre-release](https://github.com/sysprog21/kbox/releases/tag/lkl-nightly) on first build. Pre-built binaries are available for both x86_64 and aarch64. To use a custom LKL:

```bash
make LKL_DIR=/path/to/lkl   # point to a directory with liblkl.a + lkl.h
make FORCE_LKL_BUILD=1      # force a from-source LKL rebuild
```

## Quick start

Build a test rootfs image (requires `e2fsprogs`, no root needed). By default, the script auto-detects the host architecture and downloads the matching Alpine minirootfs. The `ARCH` variable can be specified to build an image for the target architecture:

```bash
# Create alpine.ext4 for the host architecture
make rootfs

# Create alpine.ext4 for aarch64
make ARCH=aarch64 CC=aarch64-linux-gnu-gcc rootfs
```

## Usage

```bash
# Interactive shell with recommended mounts + root identity (recommended)
./kbox image -S alpine.ext4 -- /bin/sh -i

# Run a specific command
./kbox image -S alpine.ext4 -- /bin/ls -la /

# Recommended mounts without root identity
./kbox image -R alpine.ext4 -- /bin/sh -i

# Raw mount only (no /proc, /sys, /dev -- for targeted commands)
./kbox image -r alpine.ext4 -- /bin/cat /etc/os-release

# Minimal mount profile (proc + tmpfs only)
./kbox image -S alpine.ext4 --mount-profile minimal -- /bin/sh -i

# Custom kernel cmdline, bind mount, explicit identity
./kbox image -r alpine.ext4 -k "mem=2048M loglevel=7" \
    -b /home/user/data:/mnt/data --change-id 1000:1000 -- /bin/sh -i
```

Note: use `/bin/sh -i` for interactive sessions. The `-i` flag forces the shell into interactive mode regardless of terminal detection.

### Syscall mode selection

The `--syscall-mode` option controls the interception mechanism:

```bash
# Auto (default): rewrite/trap for direct binaries, seccomp for shells and --net
./kbox image -S alpine.ext4 -- /bin/ls /

# Force seccomp for all workloads (most compatible, handles fork+exec)
./kbox image -S alpine.ext4 --syscall-mode=seccomp -- /bin/sh -i

# Force trap for single-exec commands (SIGSYS dispatch, no binary patching)
./kbox image -r alpine.ext4 --syscall-mode=trap -- /bin/cat /etc/hostname

# Force rewrite (aarch64: patches SVC to branch trampolines, fastest stat;
#                x86_64: patches wrapper sites, bare syscalls fall back to trap)
./kbox image -r alpine.ext4 --syscall-mode=rewrite -- /opt/tests/bench-test 200
```

Run `./kbox image --help` for the full option list.

## Web-based kernel observatory

The kernel runs in the same address space as the supervisor. Every data structure -- scheduler runqueues, page cache state, VFS dentries, slab allocator metadata -- is directly readable. kbox exploits this by sampling LKL's internal `/proc` files and streaming the data to a browser dashboard.

This is not strace. strace shows syscall arguments and return values from the outside. The web observatory shows what happens inside the kernel while processing those syscalls: context switches accumulating, page cache warming, memory allocators splitting buddy pages, softirqs firing.

Traditional kernel observation requires root (ftrace, perf), serial connections (KGDB), or kernel recompilation (printk). LKL eliminates all of these barriers. The supervisor calls `kbox_lkl_openat("/proc/stat")` and reads LKL's own procfs -- not the host's -- from an unprivileged process.

```bash
# Build with web support
make KBOX_HAS_WEB=1 BUILD=release

# Launch with observatory on default port 8080
./kbox image -S alpine.ext4 --web -- /bin/sh -i

# Custom port and bind address (e.g., access from outside a VM)
./kbox image -S alpine.ext4 --web=9090 --web-bind 0.0.0.0 -- /bin/sh -i

# JSON trace to stderr without HTTP server
./kbox image -S alpine.ext4 --trace-format json -- /bin/ls /
```

Open `http://127.0.0.1:8080/` in a browser. The dashboard shows:

- **Syscall activity**: stacked time-series of dispatch rate by family (file I/O, directory, FD ops, identity, memory, signals, scheduler). Computed as deltas between 3-second polling intervals.
- **Memory**: stacked area chart of LKL kernel memory breakdown (free, buffers, cached, slab, used) read from `/proc/meminfo`.
- **Scheduler**: context switch rate from `/proc/stat` and load average from `/proc/loadavg`.
- **Interrupts**: per-type softirq distribution (TIMER, NET_RX, NET_TX, BLOCK, SCHED, etc.) from `/proc/softirqs`.
- **Event feed**: scrolling SSE stream of individual syscall dispatches with per-call latency, color-coded by disposition, filterable, click-to-expand.
- **System gauges**: SVG arc gauges for syscalls/s, context switches/s, memory pressure, FD table occupancy.

API endpoints:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/` | GET | Dashboard SPA (compiled-in HTML/JS/CSS via `xxd -i`) |
| `/api/snapshot` | GET | Current telemetry snapshot (JSON) |
| `/api/events` | GET | SSE stream of dispatch events |
| `/api/history` | GET | Historical snapshots for chart backfill |
| `/api/enosys` | GET | Per-syscall-number ENOSYS hit counts |
| `/stats` | GET | Quick health summary |
| `/api/control` | POST | Pause/resume telemetry sampling |

Implementation details:

- The telemetry sampler runs on the main dispatch thread's poll timeout (100ms tick), reading LKL `/proc/stat`, `/proc/meminfo`, `/proc/vmstat`, `/proc/loadavg` via `kbox_lkl_openat`/`kbox_lkl_read`. A 5ms per-tick time budget prevents expensive `/proc` parsing from starving seccomp dispatch.
- The HTTP server runs in a dedicated pthread with its own epoll set. Shared state (snapshots, event ring) is protected by a single mutex. Counter fields use `atomic_int` for cross-thread flags.
- The event ring buffer holds 1024 entries split into 768 for sampled routine events (1% probabilistic sampling for high-frequency syscalls like read/write) and 256 reserved for errors and rare events (execve, clone, exit -- always captured). Events are sequence-numbered to prevent SSE duplicate delivery.
- Dispatch instrumentation adds ~25ns overhead per intercepted syscall (one `clock_gettime(CLOCK_MONOTONIC)` call before and after dispatch).
- All frontend assets (Chart.js 4.4.7, vanilla JS, CSS) are compiled into the binary via `xxd -i` at build time. No CDN, no npm, no runtime file I/O. The entire dashboard is self-contained in the kbox binary.
- When `--web` is not passed, the web subsystem is completely inert -- no threads, no sockets, no overhead. When `KBOX_HAS_WEB` is not set at build time, the web code compiles to empty translation units.

## Testing

```bash
make check                  # all tests (unit + integration + stress)
make check-unit             # unit tests under ASAN/UBSAN
make check-integration      # integration tests against a rootfs image
make check-stress           # stress test programs
```

Unit tests (portable subset runs on macOS, full suite on Linux) have no LKL dependency. Linux-only tests cover the trap runtime, userspace loader, rewrite engine, x86-64 instruction decoder, site classification, procmem, and syscall request decoding. The x86 decoder tests verify instruction length correctness across all major encoding formats and validate that embedded `0F 05` bytes inside longer instructions are not misidentified as syscalls. Integration tests run guest binaries inside kbox against an Alpine ext4 image. Stress tests exercise fork storms, FD exhaustion, concurrent I/O, signal races, and long-running processes.

All tests run clean under ASAN and UBSAN. Guest binaries are compiled without sanitizers (shadow memory interferes with `process_vm_readv`).

## GDB integration

Because LKL runs in-process, the entire kernel lives in the same address space as the supervisor. Students can set GDB breakpoints on kernel functions, read live procfs data, and trace syscall paths end-to-end -- from seccomp notification through VFS traversal down to the ext4 block layer.

```bash
# Load kbox and LKL GDB helpers
source scripts/gdb/kbox-gdb.py

# Break when a specific syscall enters dispatch
kbox-break-syscall openat

# Print the virtual FD table (LKL FD -> host FD mapping)
kbox-fdtable

# Trace path translation: lexical normalization + virtual/host routing
kbox-vfs-path /proc/../etc/passwd

# Walk LKL task list (kernel threads, idle task)
kbox-task-walk

# Inspect LKL memory state (buddy allocator, slab caches)
kbox-mem-check

# Coordinated breakpoints across seccomp dispatch and LKL kernel entry
kbox-syscall-trace
```

The GDB helpers and the web observatory read the same kernel state through different mechanisms. GDB helpers use DWARF debug info to resolve struct offsets at runtime (`gdb.parse_and_eval`). The web telemetry reads `/proc` files via `kbox_lkl_read`, which is stable across kernel versions and requires no debug info. They are complementary: the web UI shows what is happening at a high level; GDB shows why at the instruction level.

See `docs/gdb-workflow.md` for the full workflow.

## Targets

- x86_64
- aarch64

## License
`kbox` is available under a permissive MIT-style license.
Use of this source code is governed by a MIT license that can be found in the [LICENSE](LICENSE) file.
