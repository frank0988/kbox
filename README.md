# kbox

kbox boots a real Linux kernel as an in-process library ([LKL](https://github.com/lkl/linux)) and routes intercepted syscalls to it. Three interception tiers are available: seccomp-unotify (most compatible), SIGSYS trap (lower latency), and binary rewriting (near-native for process-info syscalls). The default `auto` mode selects the fastest tier that works for a given workload. kbox provides a rootless chroot/proot alternative with kernel-level syscall accuracy, and serves as a high-observability execution substrate for AI agent tool calls.

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

The default `--syscall-mode=auto` selects the fastest tier for each command. Non-shell direct binaries use rewrite/trap on both x86_64 and aarch64 (faster open+close and lseek+read via the local fast-path that bypasses the service thread for 40+ LKL-free syscalls). Shell invocations and networking commands use seccomp (fork/exec coherence and SLIRP poll loop require the supervisor). The selection is based on binary analysis: the main executable is scanned for fork/clone wrapper sites, and binaries that can fork fall back to seccomp. A guest-thread local fast-path (`kbox_dispatch_try_local_fast_path`) handles brk, futex, poll/ppoll/pselect6, munmap, mremap, madvise, sched_yield, and other host-kernel operations with zero IPC overhead (mmap and epoll are not in this set -- they go through full dispatch for W^X enforcement and FD gating). An FD-local stat cache avoids repeated LKL inode lookups for fstat on the same file descriptor. (Note: ASAN builds pin AUTO to seccomp; the trap path's guest-stack switch is incompatible with sanitizer memory tracking.)

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
   - **Rewrite**: same as trap, but additionally patches syscall instructions to branch directly into dispatch trampolines, eliminating the SIGSYS signal overhead entirely for patched sites. On aarch64, fixed-width `SVC #0` is replaced with a `B` branch to a per-site trampoline that calls the C dispatch directly on the guest thread. On x86_64, only 8-byte wrapper sites (`mov $NR; syscall; ret`) can be patched safely; bare 2-byte `syscall` instructions fall through to the trap path. W^X enforcement blocks simultaneous `PROT_WRITE|PROT_EXEC` in guest memory.
   - **Auto** (default): selects the fastest tier per command. Non-shell direct binaries whose main executable has no fork/clone wrapper sites use rewrite/trap on both x86_64 and aarch64. On aarch64, rewrite delivers ~7x faster stat (~3us vs 22us seccomp) via in-process LKL inode cache. On x86_64, trap delivers faster lseek+read (~1.4x) and open+close (~1.1x) via the guest-thread local fast-path (50+ CONTINUE syscalls bypass the service thread entirely). Shell invocations and `--net` commands always use seccomp (fork coherence and SLIRP poll loop). If the selected tier fails at install time, auto falls through to the next tier. ASAN builds pin auto to seccomp (guest-stack switch incompatible with sanitizer tracking).

Intercepted syscalls are dispatched to one of three dispositions: LKL forward (~100 handlers covering filesystem, metadata, identity, networking, and memory-mapped operations), host CONTINUE (~50 entries replayed by the host kernel for scheduling, signals, brk, futex, and similar), or emulated (process identity, uname, getrandom). All three interception tiers share a single dispatch engine (`kbox_dispatch_request`), and the `kbox_syscall_request` abstraction decouples dispatch logic from the notification transport. Over 50 dangerous syscalls (mount, reboot, init_module, bpf, ptrace, etc.) are rejected with `EPERM` directly in the BPF filter.

Key subsystem notes:

- **Virtual FD table** (`fd-table.c`): three ranges back the guest FD namespace: low FDs `0..1023` for dup2/dup3 redirection and stdio compatibility, mid FDs `1024..32767` for tracked host-passthrough descriptors, and high FDs `32768..36863` for normal LKL allocation (capped at `KBOX_FD_TABLE_MAX=4096` slots). This avoids collisions between real host FDs and virtual LKL-backed FDs.
- **Shadow FDs** (`shadow-fd.c`): regular file opens can be mirrored into host-visible memfds so native `mmap` works for dynamic linkers and other host-side loaders. Three flavors coexist: read-only sealed memfd shadows (point-in-time snapshots, no write-back), writeback shadows (dirty pages are synced back to LKL on close/fsync), and an 8-entry path shadow cache that reuses memfds across repeated reads or stats of the same path.
- **Path and ELF handling** (`path.c`, `elf.c`, `image.c`): path normalization blocks lexical and procfs-based escapes on LKL-routed paths, while ELF extraction patches `PT_INTERP` to `/proc/self/fd/N` so dynamically linked guests can exec from extracted memfds.
- **ABI translation**: LKL uses asm-generic layouts, so kbox translates structures like `stat`, sign-extends seccomp `args[]` correctly, and remaps the aarch64 `O_*` flag differences between host and guest ABIs.

## Security model

kbox reduces the host kernel attack surface via seccomp BPF filtering and routes filesystem and networking syscalls through LKL rather than the host (performance-critical operations like mmap, futex, brk, and epoll still execute on the host kernel). Over 50 dangerous syscalls (mount, reboot, init_module, bpf, ptrace, etc.) are rejected with `EPERM` in the BPF filter before reaching the supervisor. Path translation blocks escape attempts on LKL-routed filesystem paths (`..` traversal, `/proc/self/root`, symlink tricks); host-routed pseudo-filesystems (`/proc`, `/sys`, `/dev`) remain governed by the host kernel and BPF policy. W^X enforcement prevents simultaneous `PROT_WRITE|PROT_EXEC` in guest memory.

However, seccomp filtering is a [building block for sandboxes, not a sandbox itself](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html). kbox runs LKL and the supervisor in the same address space as the guest (especially in trap/rewrite mode). This design delivers low overhead and deep observability, but it means a memory-safety bug in the dispatch path or LKL could be exploitable by a crafted guest binary.

Three deployment tiers, in ascending isolation strength:

| Tier | Threat model | Setup |
|------|-------------|-------|
| kbox alone | Trusted/semi-trusted code: build tools, test suites, static analysis, research, teaching | `./kbox image -S rootfs.ext4 -- /bin/sh -i` |
| kbox + namespace/LSM | Agent tool execution with defense-in-depth: CI runners, automated code review | Wrap with `bwrap`, Landlock, or cgroup limits (adds containment and resource controls, not hardware isolation) |
| outer sandbox + kbox | Untrusted code, multi-tenant: hostile payloads, student submissions, public-facing agent APIs | Run kbox inside a microVM (Firecracker, Cloud Hypervisor) for hardware-enforced isolation, or inside gVisor for userspace-kernel isolation |

kbox is designed as an inner-layer sandbox. For hostile code containment, pair it with an outer isolation boundary. Only microVMs provide hardware-enforced address space separation; gVisor and namespace jails reduce the attack surface without hardware isolation.

## AI agent integration

AI agents that execute tool calls (compile, test, run scripts, query filesystems) need three things from their execution layer: faithful Linux behavior so tools work correctly, visibility into what happened when a tool call fails, and low per-invocation overhead so the agent loop stays fast. Typical container execution surfaces only process-level outcomes (exit code, stderr) unless you add external host-side instrumentation (cgroups, eBPF, perf); even then, host-side counters (cgroup memory.stat, cpu.stat) show resource accounting and may include slab/workingset counters, but not the guest kernel's own procfs view or full allocator internals like buddy free lists and per-cache slab details. strace shows syscall arguments from the outside but cannot see kernel-internal state like memory pressure or load average trends. kbox occupies a different point in the design space: the kernel runs in-process, so every internal data structure is directly readable by the supervisor while the guest executes.

- **Kernel-internal observability**: because LKL runs in the same address space, kbox samples `/proc/stat`, `/proc/meminfo`, `/proc/vmstat`, and `/proc/loadavg` from LKL's own procfs -- not the host's. The current telemetry API exposes context switch rates, memory breakdown (free, buffers, cached, slab), page fault counters, load averages, and per-type softirq totals (parsed from the `softirq` line in `/proc/stat`) for the guest workload specifically. When an agent tool call hangs, the orchestrator can query `/api/snapshot` to help differentiate CPU-heavy behavior from memory pressure. Deeper kernel internals (runqueues, buddy free lists, per-cache slab details) are not exported by the web API today, but because LKL is in-process they are directly inspectable via GDB. Few rootless mechanisms expose a real Linux kernel's own procfs this directly from an unprivileged process; gVisor has its own internal metrics, but kbox reads native kernel procfs without requiring a reimplemented kernel.
- **Per-syscall audit trail**: in seccomp mode (the strongest-isolation tier, and the auto-mode default for shells, networking, and ASAN builds), every intercepted syscall passes through `kbox_dispatch_request` with a `clock_gettime` measurement before and after dispatch (~25ns overhead). The SSE event stream (`/api/events`) and JSON trace mode (`--trace-format json`) produce structured records of every dispatch decision: which syscall, which disposition (LKL forward, host CONTINUE, or emulated), and how long it took. Trap and rewrite modes do not currently emit these per-syscall records; agent frameworks that need a complete trail should pin `--syscall-mode=seccomp`. The stream covers syscalls that reach the dispatch engine; BPF-denied syscalls (mount, ptrace, bpf, etc.) return EPERM before the supervisor sees them. Agent frameworks can consume this to detect runaway syscall loops, identify unsupported syscalls (ENOSYS counters via `/api/enosys`), and attribute latency to specific tool-call phases.
- **Real Linux semantics**: agents get Linux kernel semantics for VFS, ext4, and procfs via LKL -- not a userspace syscall reimplementation. Compilers, package managers, and test harnesses see real kernel behavior. This eliminates a class of agent failures where the tool works on a developer machine but breaks in the sandbox because the sandbox's syscall emulation is incomplete.
- **Low per-call overhead**: in-process LKL boot, no VM or container daemon. The `auto` mode selects the fastest interception tier per command: trap/rewrite for direct binaries (~3us stat on aarch64, ~1.4x faster lseek+read on x86_64 vs seccomp), seccomp for shell pipelines. Short-lived tool calls complete without amortizing multi-second startup costs that dominate agent latency budgets.
- **Programmable dispatch point**: the unified dispatch engine is the natural insertion point for future per-agent policy (path allowlists, socket rules, syscall quotas). All three interception tiers share this path. The underlying request abstraction (`kbox_syscall_request`) already decouples policy decisions from the notification transport, but no user-facing policy hook exists yet.
- **Deterministic initial rootfs**: the ext4 disk image provides a known starting state. For reproducible agent evaluation, mount read-only or clone the image per run; the default mount is read-write. Combined with `--syscall-mode=seccomp` (strongest isolation) and fixed kernel cmdline, this gives repeatable initial conditions for benchmark comparisons across agent runs.

### Recommended agent deployment

```
host -> [outer boundary] -> kbox -> agent tool process
```

For trusted tool execution (compilation, linting, unit tests), kbox alone is sufficient. For untrusted or adversarial inputs, wrap kbox in a namespace jail (`bwrap --unshare-all`) or a microVM. The outer boundary provides the security guarantee; kbox provides Linux semantics and observability inside it.

### Observability for agent frameworks

The observability endpoints (`/api/snapshot`, `/api/events`, `/api/enosys`) expose telemetry that agent orchestrators can consume directly:

| What to monitor | Endpoint | Why it matters |
|----------------|----------|---------------|
| Syscall rate by family | `/api/snapshot` | Detect runaway loops (e.g., agent stuck in open/close cycle) |
| ENOSYS hit counts | `/api/enosys` | Identify unsupported syscalls the guest binary needs |
| Kernel memory pressure | `/api/snapshot` | Catch OOM before the guest is killed |
| Per-call latency | `/api/events` (SSE) | Profile tool-call overhead for agent cost budgeting |

## Building

First, bootstrap with a default config.

```bash
make defconfig
```

Linux only (host kernel 5.0+ for seccomp-unotify, 5.9+ for FSGSBASE trap optimization). Requires GCC and GNU Make. `liblkl.a` is fetched automatically from a nightly pre-release on first build (see below for `LKL_DIR`/`FORCE_LKL_BUILD` overrides). No `libseccomp` dependency; the BPF filter is compiled natively.

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

The kernel runs in the same address space as the supervisor. Every data structure -- scheduler runqueues, page cache state, VFS dentries, slab allocator metadata -- is directly readable, either via the web telemetry sampler or via GDB. kbox exploits this by sampling LKL's internal `/proc` files and streaming the data to a browser dashboard.

This is not strace. strace shows syscall arguments and return values from the outside. The web observatory shows guest-kernel counters that strace cannot reach: context switches accumulating, memory pressure rising, softirq totals climbing, ENOSYS hits piling up. Note: the dashboard is currently driven by the seccomp supervisor, so it works in seccomp mode (`--syscall-mode=seccomp`, the auto default for shells and `--net`). Trap and rewrite modes do not yet drive the sampler or emit per-syscall events.

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
- **Interrupts**: per-type softirq totals (TIMER, NET_RX, NET_TX, BLOCK, SCHED, etc.) parsed from the `softirq` line in `/proc/stat`.
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

All frontend assets (Chart.js, vanilla JS, CSS) are compiled into the binary at build time -- no CDN, no npm, no runtime file I/O. When neither `--web` nor `--trace-format json` is passed, the observability subsystem is completely inert. With web telemetry or JSON tracing enabled, dispatch instrumentation in seccomp mode adds ~25ns overhead per intercepted syscall. The sampler runs on the seccomp supervisor's 100ms poll loop, and the event ring keeps 1024 entries split into 768 routine slots plus 256 reserved error/rare-event slots.

## Testing

```bash
make check                  # all tests (unit + integration + stress)
make check-unit             # unit tests under ASAN/UBSAN
make check-integration      # integration tests against a rootfs image
make check-stress           # stress test programs
```

Unit tests (portable subset runs on macOS, full suite on Linux) have no LKL dependency. The portable set includes the x86-64 instruction decoder tests, which verify instruction length correctness across all major encoding formats and validate that embedded `0F 05` bytes inside longer instructions are not misidentified as syscalls. Linux-only tests cover the trap runtime, userspace loader, rewrite engine, site classification, procmem, and syscall request decoding. Integration tests run guest binaries inside kbox against an Alpine ext4 image. Stress tests exercise fork storms, FD exhaustion, concurrent I/O, signal races, and long-running processes.

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
