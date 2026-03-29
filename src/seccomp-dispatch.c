/* SPDX-License-Identifier: MIT */

/* Syscall dispatch engine for the seccomp supervisor.
 *
 * Each intercepted syscall notification is dispatched to a handler that either
 * forwards it through LKL (RETURN) or lets host kernel handle it (CONTINUE).
 * This is the beating heart of kbox: every file open, read, write, stat, and
 * directory operation the tracee makes gets routed through here.
 *
 */

#include <errno.h>
#include <fcntl.h>
/* seccomp types via seccomp.h -> seccomp-defs.h */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include "fd-table.h"
#include "kbox/elf.h"
#include "kbox/identity.h"
#include "kbox/path.h"
#include "lkl-wrap.h"
#include "loader-launch.h"
#include "net.h"
#include "procmem.h"
#include "rewrite.h"
#include "seccomp.h"
#include "shadow-fd.h"
#include "syscall-nr.h"
#include "syscall-trap-signal.h"
#include "syscall-trap.h"

#define KBOX_FD_HOST_SAME_FD_SHADOW (-2)
#define KBOX_FD_LOCAL_ONLY_SHADOW (-3)
#define KBOX_LKL_FD_SHADOW_ONLY (-2)

/* Argument extraction helpers. */

static inline int64_t to_c_long_arg(uint64_t v)
{
    return (int64_t) v;
}

/* Static scratch buffer for I/O dispatch.  The dispatcher is single-threaded
 * and non-reentrant: only one syscall is dispatched at a time.  Using a static
 * buffer instead of malloc avoids heap allocation from the SIGSYS handler in
 * trap/rewrite mode, where the guest may hold glibc heap locks.
 */
static uint8_t dispatch_scratch[KBOX_IO_CHUNK_LEN];

static inline long to_dirfd_arg(uint64_t v)
{
    return (long) (int) (uint32_t) v;
}

static int guest_mem_read(const struct kbox_supervisor_ctx *ctx,
                          pid_t pid,
                          uint64_t remote_addr,
                          void *out,
                          size_t len);
static int guest_mem_write(const struct kbox_supervisor_ctx *ctx,
                           pid_t pid,
                           uint64_t remote_addr,
                           const void *in,
                           size_t len);
static int try_cached_shadow_open_dispatch(
    struct kbox_supervisor_ctx *ctx,
    const struct kbox_syscall_request *req,
    long flags,
    const char *translated,
    struct kbox_dispatch *out);
static int try_cached_shadow_stat_dispatch(struct kbox_supervisor_ctx *ctx,
                                           const char *translated,
                                           uint64_t remote_stat,
                                           pid_t pid);
static void invalidate_path_shadow_cache(struct kbox_supervisor_ctx *ctx);
static void invalidate_translated_path_cache(struct kbox_supervisor_ctx *ctx);

static inline void invalidate_stat_cache_fd(struct kbox_supervisor_ctx *ctx,
                                            long lkl_fd)
{
#if KBOX_STAT_CACHE_ENABLED
    for (int i = 0; i < KBOX_STAT_CACHE_MAX; i++)
        if (ctx->stat_cache[i].lkl_fd == lkl_fd)
            ctx->stat_cache[i].lkl_fd = -1;
#else
    (void) ctx;
    (void) lkl_fd;
#endif
}

/* Close an LKL FD and evict it from the stat cache.  Every LKL close in
 * the dispatch code should go through this wrapper to prevent stale fstat
 * results when the LKL FD number is reused.
 */
static inline long lkl_close_and_invalidate(struct kbox_supervisor_ctx *ctx,
                                            long lkl_fd)
{
    invalidate_stat_cache_fd(ctx, lkl_fd);
    return kbox_lkl_close(ctx->sysnrs, lkl_fd);
}

static int try_writeback_shadow_open(struct kbox_supervisor_ctx *ctx,
                                     const struct kbox_syscall_request *req,
                                     long lkl_fd,
                                     long flags,
                                     const char *translated,
                                     struct kbox_dispatch *out);
static void note_shadow_writeback_open(struct kbox_supervisor_ctx *ctx,
                                       struct kbox_fd_entry *entry);
static void note_shadow_writeback_close(struct kbox_supervisor_ctx *ctx,
                                        struct kbox_fd_entry *entry);

static int request_uses_trap_signals(const struct kbox_syscall_request *req)
{
    return req && (req->source == KBOX_SYSCALL_SOURCE_TRAP ||
                   req->source == KBOX_SYSCALL_SOURCE_REWRITE);
}

static int request_blocks_reserved_sigsys(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    uint64_t set_ptr;
    size_t sigset_size;
    unsigned char mask[16];
    size_t read_len;
    int rc;

    if (!req)
        return 0;
    set_ptr = kbox_syscall_request_arg(req, 1);
    sigset_size = (size_t) kbox_syscall_request_arg(req, 3);
    if (set_ptr == 0 || sigset_size == 0)
        return 0;

    read_len = sigset_size;
    if (read_len > sizeof(mask))
        read_len = sizeof(mask);
    memset(mask, 0, sizeof(mask));

    rc = guest_mem_read(ctx, kbox_syscall_request_pid(req), set_ptr, mask,
                        read_len);
    if (rc < 0)
        return rc;

    return kbox_syscall_trap_sigset_blocks_reserved(mask, read_len) ? 1 : 0;
}

static struct kbox_fd_entry *fd_table_entry(struct kbox_fd_table *t, long fd)
{
    if (!t)
        return NULL;
    if (fd >= KBOX_FD_BASE && fd < KBOX_FD_BASE + KBOX_FD_TABLE_MAX)
        return &t->entries[fd - KBOX_FD_BASE];
    if (fd >= 0 && fd < KBOX_LOW_FD_MAX)
        return &t->low_fds[fd];
    return NULL;
}

static struct kbox_dispatch emulate_trap_rt_sigprocmask(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long how = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    uint64_t set_ptr = kbox_syscall_request_arg(req, 1);
    uint64_t old_ptr = kbox_syscall_request_arg(req, 2);
    size_t sigset_size = (size_t) kbox_syscall_request_arg(req, 3);
    unsigned char current[sizeof(sigset_t)];
    unsigned char next[sizeof(sigset_t)];
    unsigned char pending[sizeof(sigset_t)];
    unsigned char set_mask[sizeof(sigset_t)];
    size_t mask_len;

    if (sigset_size == 0 || sigset_size > sizeof(current))
        return kbox_dispatch_errno(EINVAL);
    mask_len = sigset_size;

    /* In TRAP mode the signal mask lives in the ucontext delivered by the
     * kernel; modifying it there takes effect when the handler returns.
     * In REWRITE mode there is no ucontext -- the rewrite dispatch runs
     * as a normal function call, so fall back to sigprocmask(2) directly.
     */
    if (kbox_syscall_trap_get_sigmask(current, sizeof(current)) < 0) {
        sigset_t tmp;
        if (sigprocmask(SIG_SETMASK, NULL, &tmp) < 0)
            return kbox_dispatch_errno(EIO);
        memcpy(current, &tmp, sizeof(current));
    }

    memset(set_mask, 0, sizeof(set_mask));
    memcpy(next, current, sizeof(next));

    if (set_ptr != 0) {
        int rc = guest_mem_read(ctx, kbox_syscall_request_pid(req), set_ptr,
                                set_mask, mask_len);
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
    }

    if (old_ptr != 0) {
        int rc = guest_mem_write(ctx, kbox_syscall_request_pid(req), old_ptr,
                                 current, mask_len);
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
    }

    if (set_ptr != 0) {
        switch (how) {
        case SIG_BLOCK:
            for (size_t i = 0; i < mask_len; i++)
                next[i] |= set_mask[i];
            break;
        case SIG_UNBLOCK:
            for (size_t i = 0; i < mask_len; i++)
                next[i] &= (unsigned char) ~set_mask[i];
            break;
        case SIG_SETMASK:
            memcpy(next, set_mask, mask_len);
            break;
        default:
            return kbox_dispatch_errno(EINVAL);
        }
    }

    if (kbox_syscall_trap_set_sigmask(next, sizeof(next)) < 0) {
        sigset_t apply;
        memcpy(&apply, next, sizeof(next));
        if (sigprocmask(SIG_SETMASK, &apply, NULL) < 0)
            return kbox_dispatch_errno(EIO);
    }

    if (kbox_syscall_trap_get_pending(pending, sizeof(pending)) == 0) {
        for (size_t i = 0; i < sizeof(pending); i++)
            pending[i] &= next[i];
        (void) kbox_syscall_trap_set_pending(pending, sizeof(pending));
    }

    return kbox_dispatch_value(0);
}

static int trap_sigmask_contains_signal(int signo)
{
    sigset_t current;

    if (signo <= 0)
        return 0;
    if (kbox_syscall_trap_get_sigmask(&current, sizeof(current)) < 0)
        return 0;
    return sigismember(&current, signo) == 1;
}

static struct kbox_dispatch emulate_trap_rt_sigpending(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    uint64_t set_ptr = kbox_syscall_request_arg(req, 0);
    size_t sigset_size = (size_t) kbox_syscall_request_arg(req, 1);
    unsigned char pending[sizeof(sigset_t)];
    int rc;

    (void) ctx;

    if (set_ptr == 0)
        return kbox_dispatch_errno(EFAULT);
    if (sigset_size == 0 || sigset_size > sizeof(pending))
        return kbox_dispatch_errno(EINVAL);
    if (kbox_syscall_trap_get_pending(pending, sizeof(pending)) < 0)
        return kbox_dispatch_errno(EIO);

    rc = guest_mem_write(ctx, kbox_syscall_request_pid(req), set_ptr, pending,
                         sigset_size);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);
    return kbox_dispatch_value(0);
}

struct kbox_fd_inject_ops {
    int (*addfd)(const struct kbox_supervisor_ctx *ctx,
                 uint64_t cookie,
                 int srcfd,
                 uint32_t newfd_flags);
    int (*addfd_at)(const struct kbox_supervisor_ctx *ctx,
                    uint64_t cookie,
                    int srcfd,
                    int target_fd,
                    uint32_t newfd_flags);
};

static int seccomp_request_addfd(const struct kbox_supervisor_ctx *ctx,
                                 uint64_t cookie,
                                 int srcfd,
                                 uint32_t newfd_flags)
{
    return kbox_notify_addfd(ctx->listener_fd, cookie, srcfd, newfd_flags);
}

static int seccomp_request_addfd_at(const struct kbox_supervisor_ctx *ctx,
                                    uint64_t cookie,
                                    int srcfd,
                                    int target_fd,
                                    uint32_t newfd_flags)
{
    return kbox_notify_addfd_at(ctx->listener_fd, cookie, srcfd, target_fd,
                                newfd_flags);
}

static const struct kbox_fd_inject_ops seccomp_fd_inject_ops = {
    .addfd = seccomp_request_addfd,
    .addfd_at = seccomp_request_addfd_at,
};

static int local_request_addfd(const struct kbox_supervisor_ctx *ctx,
                               uint64_t cookie,
                               int srcfd,
                               uint32_t newfd_flags)
{
    int ret;

    (void) ctx;
    (void) cookie;
#ifdef F_DUPFD_CLOEXEC
    if (newfd_flags & O_CLOEXEC) {
        ret = (int) kbox_syscall_trap_host_syscall6(SYS_fcntl, (uint64_t) srcfd,
                                                    (uint64_t) F_DUPFD_CLOEXEC,
                                                    0, 0, 0, 0);
        return ret >= 0 ? ret : -(int) -ret;
    }
#endif
    ret = (int) kbox_syscall_trap_host_syscall6(SYS_fcntl, (uint64_t) srcfd,
                                                (uint64_t) F_DUPFD, 0, 0, 0, 0);
    return ret >= 0 ? ret : -(int) -ret;
}

static int local_request_addfd_at(const struct kbox_supervisor_ctx *ctx,
                                  uint64_t cookie,
                                  int srcfd,
                                  int target_fd,
                                  uint32_t newfd_flags)
{
    (void) ctx;
    (void) cookie;
#ifdef __linux__
    {
        int ret = (int) kbox_syscall_trap_host_syscall6(
            SYS_dup3, (uint64_t) srcfd, (uint64_t) target_fd,
            (uint64_t) ((newfd_flags & O_CLOEXEC) ? O_CLOEXEC : 0), 0, 0, 0);
        return ret >= 0 ? ret : -(int) -ret;
    }
#else
    (void) srcfd;
    (void) target_fd;
    (void) newfd_flags;
    return -ENOSYS;
#endif
}

static const struct kbox_fd_inject_ops local_fd_inject_ops = {
    .addfd = local_request_addfd,
    .addfd_at = local_request_addfd_at,
};

static int request_addfd(const struct kbox_supervisor_ctx *ctx,
                         const struct kbox_syscall_request *req,
                         int srcfd,
                         uint32_t newfd_flags)
{
    if (!ctx || !ctx->fd_inject_ops || !ctx->fd_inject_ops->addfd || !req)
        return -EINVAL;
    return ctx->fd_inject_ops->addfd(ctx, kbox_syscall_request_cookie(req),
                                     srcfd, newfd_flags);
}

static int request_addfd_at(const struct kbox_supervisor_ctx *ctx,
                            const struct kbox_syscall_request *req,
                            int srcfd,
                            int target_fd,
                            uint32_t newfd_flags)
{
    if (!ctx || !ctx->fd_inject_ops || !ctx->fd_inject_ops->addfd_at || !req)
        return -EINVAL;
    return ctx->fd_inject_ops->addfd_at(ctx, kbox_syscall_request_cookie(req),
                                        srcfd, target_fd, newfd_flags);
}

void kbox_dispatch_prepare_request_ctx(struct kbox_supervisor_ctx *ctx,
                                       const struct kbox_syscall_request *req)
{
    if (!ctx || !req)
        return;

    ctx->active_guest_mem = req->guest_mem;
    if (!ctx->active_guest_mem.ops) {
        ctx->active_guest_mem.ops = &kbox_process_vm_guest_mem_ops;
        ctx->active_guest_mem.opaque = (uintptr_t) req->pid;
    }
    ctx->guest_mem_ops = ctx->active_guest_mem.ops;
    if (!ctx->fd_inject_ops) {
        if (req->source == KBOX_SYSCALL_SOURCE_TRAP ||
            req->source == KBOX_SYSCALL_SOURCE_REWRITE) {
            ctx->fd_inject_ops = &local_fd_inject_ops;
        } else {
            ctx->fd_inject_ops = &seccomp_fd_inject_ops;
        }
    }
}

static int guest_mem_read(const struct kbox_supervisor_ctx *ctx,
                          pid_t pid,
                          uint64_t remote_addr,
                          void *out,
                          size_t len)
{
    (void) pid;
    return kbox_guest_mem_read(&ctx->active_guest_mem, remote_addr, out, len);
}

static int guest_mem_write(const struct kbox_supervisor_ctx *ctx,
                           pid_t pid,
                           uint64_t remote_addr,
                           const void *in,
                           size_t len)
{
    (void) pid;
    return kbox_guest_mem_write(&ctx->active_guest_mem, remote_addr, in, len);
}

static int guest_mem_write_force(const struct kbox_supervisor_ctx *ctx,
                                 pid_t pid,
                                 uint64_t remote_addr,
                                 const void *in,
                                 size_t len)
{
    (void) pid;
    return kbox_guest_mem_write_force(&ctx->active_guest_mem, remote_addr, in,
                                      len);
}

static int guest_mem_read_string(const struct kbox_supervisor_ctx *ctx,
                                 pid_t pid,
                                 uint64_t remote_addr,
                                 char *buf,
                                 size_t max_len)
{
    (void) pid;
    return kbox_guest_mem_read_string(&ctx->active_guest_mem, remote_addr, buf,
                                      max_len);
}

static int guest_mem_read_open_how(const struct kbox_supervisor_ctx *ctx,
                                   pid_t pid,
                                   uint64_t remote_addr,
                                   uint64_t size,
                                   struct kbox_open_how *out)
{
    (void) pid;

    return kbox_guest_mem_read_open_how(&ctx->active_guest_mem, remote_addr,
                                        size, out);
}

/* Open-flag ABI translation (aarch64 host <-> asm-generic LKL). */

/* aarch64 and asm-generic define four O_* flags differently:
 *
 *   Flag         aarch64     asm-generic (LKL)
 *   O_DIRECTORY  0x04000     0x10000
 *   O_NOFOLLOW   0x08000     0x20000
 *   O_DIRECT     0x10000     0x04000
 *   O_LARGEFILE  0x20000     0x08000
 *
 * x86_64 values already match asm-generic so no translation is needed there.
 */
#if defined(__aarch64__)

#define HOST_O_DIRECTORY 0x04000
#define HOST_O_NOFOLLOW 0x08000
#define HOST_O_DIRECT 0x10000
#define HOST_O_LARGEFILE 0x20000

#define LKL_O_DIRECTORY 0x10000
#define LKL_O_NOFOLLOW 0x20000
#define LKL_O_DIRECT 0x04000
#define LKL_O_LARGEFILE 0x08000

static inline long host_to_lkl_open_flags(long flags)
{
    long out = flags & ~(HOST_O_DIRECTORY | HOST_O_NOFOLLOW | HOST_O_DIRECT |
                         HOST_O_LARGEFILE);
    if (flags & HOST_O_DIRECTORY)
        out |= LKL_O_DIRECTORY;
    if (flags & HOST_O_NOFOLLOW)
        out |= LKL_O_NOFOLLOW;
    if (flags & HOST_O_DIRECT)
        out |= LKL_O_DIRECT;
    if (flags & HOST_O_LARGEFILE)
        out |= LKL_O_LARGEFILE;
    return out;
}

static inline long lkl_to_host_open_flags(long flags)
{
    long out = flags & ~(LKL_O_DIRECTORY | LKL_O_NOFOLLOW | LKL_O_DIRECT |
                         LKL_O_LARGEFILE);
    if (flags & LKL_O_DIRECTORY)
        out |= HOST_O_DIRECTORY;
    if (flags & LKL_O_NOFOLLOW)
        out |= HOST_O_NOFOLLOW;
    if (flags & LKL_O_DIRECT)
        out |= HOST_O_DIRECT;
    if (flags & LKL_O_LARGEFILE)
        out |= HOST_O_LARGEFILE;
    return out;
}

#else /* x86_64: flags already match asm-generic */

static inline long host_to_lkl_open_flags(long flags)
{
    return flags;
}

static inline long lkl_to_host_open_flags(long flags)
{
    return flags;
}

#endif

/* Stat ABI conversion. */

/* Convert LKL's generic-arch stat layout to the host's struct stat.
 *
 * LKL always fills stat buffers using the asm-generic layout regardless of the
 * host architecture. On x86_64 the two layouts differ:
 *   generic: st_mode (u32) at offset 16, st_nlink (u32) at offset 20
 *   x86_64:  st_nlink (u64) at offset 16, st_mode (u32) at offset 24
 *
 * On aarch64 the kernel uses the generic layout, but the C library's struct
 * stat may still have different padding, so convert explicitly on all
 * architectures.
 */
static void kbox_lkl_stat_to_host(const struct kbox_lkl_stat *src,
                                  struct stat *dst)
{
    memset(dst, 0, sizeof(*dst));
    dst->st_dev = (dev_t) src->st_dev;
    dst->st_ino = (ino_t) src->st_ino;
    dst->st_mode = (mode_t) src->st_mode;
    dst->st_nlink = (nlink_t) src->st_nlink;
    dst->st_uid = (uid_t) src->st_uid;
    dst->st_gid = (gid_t) src->st_gid;
    dst->st_rdev = (dev_t) src->st_rdev;
    dst->st_size = (off_t) src->st_size;
    dst->st_blksize = (blksize_t) src->st_blksize;
    dst->st_blocks = (blkcnt_t) src->st_blocks;
    dst->st_atim.tv_sec = (time_t) src->st_atime_sec;
    dst->st_atim.tv_nsec = (long) src->st_atime_nsec;
    dst->st_mtim.tv_sec = (time_t) src->st_mtime_sec;
    dst->st_mtim.tv_nsec = (long) src->st_mtime_nsec;
    dst->st_ctim.tv_sec = (time_t) src->st_ctime_sec;
    dst->st_ctim.tv_nsec = (long) src->st_ctime_nsec;
}

/* Dispatch result constructors. */

struct kbox_dispatch kbox_dispatch_continue(void)
{
    return (struct kbox_dispatch) {
        .kind = KBOX_DISPATCH_CONTINUE,
        .val = 0,
        .error = 0,
    };
}

struct kbox_dispatch kbox_dispatch_errno(int err)
{
    if (err <= 0)
        err = EIO;
    return (struct kbox_dispatch) {
        .kind = KBOX_DISPATCH_RETURN,
        .val = 0,
        .error = err,
    };
}

struct kbox_dispatch kbox_dispatch_value(int64_t val)
{
    return (struct kbox_dispatch) {
        .kind = KBOX_DISPATCH_RETURN,
        .val = val,
        .error = 0,
    };
}

struct kbox_dispatch kbox_dispatch_from_lkl(long ret)
{
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));
    return kbox_dispatch_value((int64_t) ret);
}

/* Path and FD helper functions. */

/* Resolve dirfd for *at() syscalls.
 *
 * If the path is absolute, AT_FDCWD is fine regardless of dirfd.  If the
 * dirfd is AT_FDCWD, pass it through.  Otherwise look up the virtual FD in
 * the table to get the LKL fd.  Returns -1 if the fd is not in the table
 * (caller should CONTINUE).
 */
static long resolve_open_dirfd(const char *path,
                               long dirfd,
                               const struct kbox_fd_table *table)
{
    if (path[0] == '/')
        return AT_FDCWD_LINUX;
    if (dirfd == AT_FDCWD_LINUX)
        return AT_FDCWD_LINUX;
    return kbox_fd_table_get_lkl(table, dirfd);
}

static int read_guest_string(const struct kbox_supervisor_ctx *ctx,
                             pid_t pid,
                             uint64_t addr,
                             char *buf,
                             size_t size)
{
    return guest_mem_read_string(ctx, pid, addr, buf, size);
}

static struct kbox_translated_path_cache_entry *find_translated_path_cache(
    struct kbox_supervisor_ctx *ctx,
    const char *guest_path)
{
    size_t i;

    if (!ctx || !guest_path)
        return NULL;
    for (i = 0; i < KBOX_TRANSLATED_PATH_CACHE_MAX; i++) {
        struct kbox_translated_path_cache_entry *entry =
            &ctx->translated_path_cache[i];
        if (entry->valid &&
            entry->generation == ctx->path_translation_generation &&
            strcmp(entry->guest_path, guest_path) == 0) {
            return entry;
        }
    }
    return NULL;
}

static struct kbox_translated_path_cache_entry *reserve_translated_path_cache(
    struct kbox_supervisor_ctx *ctx)
{
    size_t i;

    if (!ctx)
        return NULL;
    for (i = 0; i < KBOX_TRANSLATED_PATH_CACHE_MAX; i++) {
        if (!ctx->translated_path_cache[i].valid)
            return &ctx->translated_path_cache[i];
    }
    return &ctx->translated_path_cache[0];
}

static struct kbox_literal_path_cache_entry *find_literal_path_cache(
    struct kbox_supervisor_ctx *ctx,
    pid_t pid,
    uint64_t guest_addr)
{
    size_t i;

    if (!ctx || guest_addr == 0)
        return NULL;
    for (i = 0; i < KBOX_LITERAL_PATH_CACHE_MAX; i++) {
        struct kbox_literal_path_cache_entry *entry =
            &ctx->literal_path_cache[i];
        if (entry->valid &&
            entry->generation == ctx->path_translation_generation &&
            entry->pid == pid && entry->guest_addr == guest_addr) {
            return entry;
        }
    }
    return NULL;
}

static struct kbox_literal_path_cache_entry *reserve_literal_path_cache(
    struct kbox_supervisor_ctx *ctx)
{
    size_t i;

    if (!ctx)
        return NULL;
    for (i = 0; i < KBOX_LITERAL_PATH_CACHE_MAX; i++) {
        if (!ctx->literal_path_cache[i].valid)
            return &ctx->literal_path_cache[i];
    }
    return &ctx->literal_path_cache[0];
}

static int guest_addr_is_writable(pid_t pid, uint64_t addr)
{
    char maps_path[64];
    FILE *fp;
    char line[256];

    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", (int) pid);
    fp = fopen(maps_path, "re");
    if (!fp)
        return 1;

    while (fgets(line, sizeof(line), fp)) {
        unsigned long long start, end;
        char perms[8];

        if (sscanf(line, "%llx-%llx %7s", &start, &end, perms) != 3)
            continue;
        if (addr < start || addr >= end)
            continue;
        fclose(fp);
        return strchr(perms, 'w') != NULL;
    }

    fclose(fp);
    return 1;
}

static void invalidate_translated_path_cache(struct kbox_supervisor_ctx *ctx)
{
    size_t i;

    if (!ctx)
        return;
    ctx->path_translation_generation++;
    for (i = 0; i < KBOX_TRANSLATED_PATH_CACHE_MAX; i++)
        ctx->translated_path_cache[i].valid = 0;
    for (i = 0; i < KBOX_LITERAL_PATH_CACHE_MAX; i++)
        ctx->literal_path_cache[i].valid = 0;
}

static int translate_guest_path(const struct kbox_supervisor_ctx *ctx,
                                pid_t pid,
                                uint64_t addr,
                                const char *host_root,
                                char *translated,
                                size_t size)
{
    struct kbox_supervisor_ctx *mutable_ctx =
        (struct kbox_supervisor_ctx *) ctx;
    char pathbuf[KBOX_MAX_PATH];
    struct kbox_literal_path_cache_entry *literal_entry;
    struct kbox_translated_path_cache_entry *entry;

    literal_entry = find_literal_path_cache(mutable_ctx, pid, addr);
    if (literal_entry) {
        size_t len = strlen(literal_entry->translated);

        if (len >= size)
            return -ENAMETOOLONG;
        memcpy(translated, literal_entry->translated, len + 1);
        return 0;
    }

    int rc = read_guest_string(ctx, pid, addr, pathbuf, sizeof(pathbuf));
    if (rc < 0)
        return rc;

    entry = find_translated_path_cache(mutable_ctx, pathbuf);
    if (entry) {
        if (strlen(entry->translated) >= size)
            return -ENAMETOOLONG;
        memcpy(translated, entry->translated, strlen(entry->translated) + 1);
        return 0;
    }

    rc = kbox_translate_path_for_lkl(pid, pathbuf, host_root, translated, size);
    if (rc < 0)
        return rc;

    entry = reserve_translated_path_cache(mutable_ctx);
    if (entry) {
        entry->valid = 1;
        entry->generation = mutable_ctx->path_translation_generation;
        strncpy(entry->guest_path, pathbuf, sizeof(entry->guest_path) - 1);
        entry->guest_path[sizeof(entry->guest_path) - 1] = '\0';
        strncpy(entry->translated, translated, sizeof(entry->translated) - 1);
        entry->translated[sizeof(entry->translated) - 1] = '\0';
    }

    if (!guest_addr_is_writable(pid, addr)) {
        literal_entry = reserve_literal_path_cache(mutable_ctx);
        if (literal_entry) {
            literal_entry->valid = 1;
            literal_entry->generation =
                mutable_ctx->path_translation_generation;
            literal_entry->pid = pid;
            literal_entry->guest_addr = addr;
            strncpy(literal_entry->translated, translated,
                    sizeof(literal_entry->translated) - 1);
            literal_entry->translated[sizeof(literal_entry->translated) - 1] =
                '\0';
        }
    }
    return 0;
}

static int translate_request_path(const struct kbox_syscall_request *req,
                                  const struct kbox_supervisor_ctx *ctx,
                                  size_t path_idx,
                                  const char *host_root,
                                  char *translated,
                                  size_t size)
{
    return translate_guest_path(ctx, kbox_syscall_request_pid(req),
                                kbox_syscall_request_arg(req, path_idx),
                                host_root, translated, size);
}

static int translate_request_at_path(const struct kbox_syscall_request *req,
                                     struct kbox_supervisor_ctx *ctx,
                                     size_t dirfd_idx,
                                     size_t path_idx,
                                     char *translated,
                                     size_t size,
                                     long *lkl_dirfd)
{
    int rc = translate_request_path(req, ctx, path_idx, ctx->host_root,
                                    translated, size);
    if (rc < 0)
        return rc;

    *lkl_dirfd = resolve_open_dirfd(
        translated, to_dirfd_arg(kbox_syscall_request_arg(req, dirfd_idx)),
        ctx->fd_table);
    return 0;
}

static int should_continue_for_dirfd(long lkl_dirfd)
{
    return lkl_dirfd < 0 && lkl_dirfd != AT_FDCWD_LINUX;
}

static int child_fd_is_open(const struct kbox_supervisor_ctx *ctx, long fd)
{
    char link_path[64];
    char target[1];

    if (!ctx || ctx->child_pid <= 0 || fd < 0)
        return 0;
    snprintf(link_path, sizeof(link_path), "/proc/%d/fd/%ld",
             (int) ctx->child_pid, fd);
    if (readlink(link_path, target, sizeof(target)) >= 0)
        return 1;
    return errno != ENOENT;
}

static long allocate_passthrough_hostonly_fd(struct kbox_supervisor_ctx *ctx)
{
    long base_fd = KBOX_FD_HOSTONLY_BASE;
    long end_fd = KBOX_FD_BASE + KBOX_FD_TABLE_MAX;
    long start_fd;
    long fd;

    if (!ctx || !ctx->fd_table)
        return -1;

    start_fd = ctx->fd_table->next_hostonly_fd;
    if (start_fd < base_fd || start_fd >= end_fd)
        start_fd = base_fd;

    for (fd = start_fd; fd < end_fd; fd++) {
        if (!child_fd_is_open(ctx, fd)) {
            ctx->fd_table->next_hostonly_fd = fd + 1;
            return fd;
        }
    }
    for (fd = base_fd; fd < start_fd; fd++) {
        if (!child_fd_is_open(ctx, fd)) {
            ctx->fd_table->next_hostonly_fd = fd + 1;
            return fd;
        }
    }

    return -1;
}

static long next_hostonly_fd_hint(const struct kbox_supervisor_ctx *ctx)
{
    long fd;
    long end_fd = KBOX_FD_BASE + KBOX_FD_TABLE_MAX;

    if (!ctx || !ctx->fd_table)
        return -1;

    fd = ctx->fd_table->next_hostonly_fd;
    if (fd < KBOX_FD_HOSTONLY_BASE || fd >= end_fd)
        fd = KBOX_FD_HOSTONLY_BASE;
    return fd;
}

static int ensure_proc_self_fd_dir(struct kbox_supervisor_ctx *ctx)
{
    if (!ctx)
        return -1;
    if (ctx->proc_self_fd_dirfd >= 0)
        return ctx->proc_self_fd_dirfd;

    ctx->proc_self_fd_dirfd =
        open("/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    return ctx->proc_self_fd_dirfd;
}

static int ensure_proc_mem_fd(struct kbox_supervisor_ctx *ctx)
{
    char path[64];

    if (!ctx || ctx->child_pid <= 0)
        return -1;
    if (ctx->proc_mem_fd >= 0)
        return ctx->proc_mem_fd;

    snprintf(path, sizeof(path), "/proc/%d/mem", (int) ctx->child_pid);
    ctx->proc_mem_fd = open(path, O_RDWR | O_CLOEXEC);
    return ctx->proc_mem_fd;
}

static int guest_mem_write_small_metadata(const struct kbox_supervisor_ctx *ctx,
                                          pid_t pid,
                                          uint64_t remote_addr,
                                          const void *in,
                                          size_t len)
{
    struct kbox_supervisor_ctx *mutable_ctx =
        (struct kbox_supervisor_ctx *) ctx;
    ssize_t n;
    int fd;

    if (!ctx || !in)
        return -EFAULT;
    if (len == 0)
        return 0;
    if (remote_addr == 0)
        return -EFAULT;
    if (pid != ctx->child_pid ||
        ctx->active_guest_mem.ops != &kbox_process_vm_guest_mem_ops)
        return guest_mem_write(ctx, pid, remote_addr, in, len);

    fd = ensure_proc_mem_fd(mutable_ctx);
    if (fd < 0)
        return guest_mem_write(ctx, pid, remote_addr, in, len);

    n = pwrite(fd, in, len, (off_t) remote_addr);
    if (n < 0)
        return guest_mem_write(ctx, pid, remote_addr, in, len);
    if ((size_t) n != len)
        return -EIO;
    return 0;
}

static int reopen_cached_shadow_fd(
    struct kbox_supervisor_ctx *ctx,
    const struct kbox_path_shadow_cache_entry *entry)
{
    char fd_name[32];
    int dirfd;
    int fd;

    if (!entry)
        return -1;
    if (entry->path[0] != '\0') {
        fd = open(entry->path, O_RDONLY | O_CLOEXEC);
        if (fd >= 0)
            return fd;
    }
    fd = entry->memfd;
    if (fd < 0)
        return -1;
    dirfd = ensure_proc_self_fd_dir(ctx);
    if (dirfd < 0)
        return -1;
    snprintf(fd_name, sizeof(fd_name), "%d", fd);
    return openat(dirfd, fd_name, O_RDONLY | O_CLOEXEC);
}

/* Promote a read-only regular LKL FD to a host-visible shadow at the same
 * guest FD number on first eligible read-only access. This avoids paying the
 * memfd copy cost at open time while still letting later read/lseek/fstat/mmap
 * operations run on a real host FD.
 *
 * Returns:
 *   1  shadow is available (same-fd injected for seccomp, local-only for
 *      trap/rewrite)
 *   0  shadow promotion not applicable
 *  -1  promotion attempted but failed
 */
static int ensure_same_fd_shadow(struct kbox_supervisor_ctx *ctx,
                                 const struct kbox_syscall_request *req,
                                 long fd,
                                 long lkl_fd)
{
    struct kbox_fd_entry *entry;
    long flags;
    int memfd;

    off_t cur_off;

    if (!ctx || !req || !ctx->fd_table || fd < 0 || lkl_fd < 0)
        return 0;

    entry = fd_table_entry(ctx->fd_table, fd);
    if (!entry)
        return 0;
    if (entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW ||
        entry->host_fd == KBOX_FD_LOCAL_ONLY_SHADOW) {
        return 1;
    }
    if (entry->host_fd >= 0)
        return 0;

    flags = kbox_lkl_fcntl(ctx->sysnrs, lkl_fd, F_GETFL, 0);
    if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY)
        return 0;

    memfd = kbox_shadow_create(ctx->sysnrs, lkl_fd);
    if (memfd < 0)
        return -1;
    kbox_shadow_seal(memfd);

    cur_off = (off_t) kbox_lkl_lseek(ctx->sysnrs, lkl_fd, 0, SEEK_CUR);
    if (cur_off >= 0 && lseek(memfd, cur_off, SEEK_SET) < 0) {
        close(memfd);
        return -1;
    }

    if (req->source == KBOX_SYSCALL_SOURCE_SECCOMP) {
        int injected = request_addfd_at(ctx, req, memfd, (int) fd,
                                        entry->cloexec ? O_CLOEXEC : 0);
        if (injected < 0) {
            close(memfd);
            return -1;
        }
        entry->host_fd = KBOX_FD_HOST_SAME_FD_SHADOW;
    } else {
        entry->host_fd = KBOX_FD_LOCAL_ONLY_SHADOW;
    }
    entry->shadow_sp = memfd;
    entry->shadow_writeback = 0;

    if (ctx->verbose) {
        fprintf(stderr, "kbox: lazy shadow promote fd=%ld lkl_fd=%ld mode=%s\n",
                fd, lkl_fd,
                entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW ? "same-fd"
                                                              : "local-only");
    }
    return 1;
}

static struct kbox_dispatch forward_local_shadow_read_like(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    struct kbox_fd_entry *entry,
    long lkl_fd,
    int is_pread)
{
    uint64_t remote_buf = kbox_syscall_request_arg(req, 1);
    int64_t count_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    size_t count;
    size_t total = 0;
    uint8_t *scratch = dispatch_scratch;
    pid_t pid = kbox_syscall_request_pid(req);

    if (!entry || entry->shadow_sp < 0)
        return kbox_dispatch_continue();
    if (count_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);
    count = (size_t) count_raw;
    if (count == 0)
        return kbox_dispatch_value(0);
    if (count > 1024 * 1024)
        count = 1024 * 1024;

    while (total < count) {
        size_t chunk_len = KBOX_IO_CHUNK_LEN;
        ssize_t nr;

        if (chunk_len > count - total)
            chunk_len = count - total;
        if (is_pread) {
            long offset = to_c_long_arg(kbox_syscall_request_arg(req, 3));
            nr = pread(entry->shadow_sp, scratch, chunk_len,
                       (off_t) (offset + (long) total));
        } else {
            nr = read(entry->shadow_sp, scratch, chunk_len);
        }
        if (nr < 0) {
            if (total == 0)
                return kbox_dispatch_errno(errno);
            break;
        }
        if (nr == 0)
            break;
        if (guest_mem_write(ctx, pid, remote_buf + total, scratch,
                            (size_t) nr) < 0) {
            return kbox_dispatch_errno(EFAULT);
        }
        total += (size_t) nr;
        if ((size_t) nr < chunk_len)
            break;
    }

    if (!is_pread) {
        off_t cur_off = lseek(entry->shadow_sp, 0, SEEK_CUR);
        if (cur_off >= 0)
            (void) kbox_lkl_lseek(ctx->sysnrs, lkl_fd, (long) cur_off,
                                  SEEK_SET);
    }

    return kbox_dispatch_value((int64_t) total);
}

static struct kbox_dispatch forward_local_shadow_lseek(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    struct kbox_fd_entry *entry,
    long lkl_fd)
{
    long off;
    long whence;
    off_t ret;

    if (!entry || entry->shadow_sp < 0)
        return kbox_dispatch_continue();

    off = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    whence = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    ret = lseek(entry->shadow_sp, (off_t) off, (int) whence);
    if (ret < 0)
        return kbox_dispatch_errno(errno);

    (void) kbox_lkl_lseek(ctx->sysnrs, lkl_fd, (long) ret, SEEK_SET);
    return kbox_dispatch_value((int64_t) ret);
}

static struct kbox_dispatch forward_local_shadow_fstat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    struct kbox_fd_entry *entry)
{
    struct stat host_stat;
    uint64_t remote_stat = kbox_syscall_request_arg(req, 1);

    if (!entry || entry->shadow_sp < 0)
        return kbox_dispatch_continue();
    if (remote_stat == 0)
        return kbox_dispatch_errno(EFAULT);
    if (fstat(entry->shadow_sp, &host_stat) < 0)
        return kbox_dispatch_errno(errno);
    if (guest_mem_write(ctx, kbox_syscall_request_pid(req), remote_stat,
                        &host_stat, sizeof(host_stat)) < 0) {
        return kbox_dispatch_errno(EFAULT);
    }
    return kbox_dispatch_value(0);
}

/* statx struct field offsets (standard on x86_64 and aarch64). */
#define STATX_MODE_OFFSET 0x20
#define STATX_UID_OFFSET 0x48
#define STATX_GID_OFFSET 0x4c
#define STATX_BUF_SIZE 0x100

static struct kbox_dispatch finish_open_dispatch(
    struct kbox_supervisor_ctx *ctx,
    const struct kbox_syscall_request *req,
    long lkl_fd,
    long flags,
    const char *translated)
{
    struct kbox_dispatch shadow_dispatch;

    if (req && try_cached_shadow_open_dispatch(ctx, req, flags, translated,
                                               &shadow_dispatch)) {
        return shadow_dispatch;
    }

    if (req && try_writeback_shadow_open(ctx, req, lkl_fd, flags, translated,
                                         &shadow_dispatch)) {
        return shadow_dispatch;
    }

    long vfd = kbox_fd_table_insert(ctx->fd_table, lkl_fd,
                                    kbox_is_tty_like_path(translated));
    if (vfd < 0) {
        lkl_close_and_invalidate(ctx, lkl_fd);
        return kbox_dispatch_errno(EMFILE);
    }
    if (flags & O_CLOEXEC)
        kbox_fd_table_set_cloexec(ctx->fd_table, vfd, 1);
    return kbox_dispatch_value((int64_t) vfd);
}

static void normalize_host_stat_if_needed(struct kbox_supervisor_ctx *ctx,
                                          const char *path,
                                          struct stat *host_stat)
{
    if (!ctx->normalize)
        return;

    uint32_t n_mode, n_uid, n_gid;
    if (!kbox_normalized_permissions(path, &n_mode, &n_uid, &n_gid))
        return;

    host_stat->st_mode = (host_stat->st_mode & S_IFMT) | (n_mode & ~S_IFMT);
    host_stat->st_uid = n_uid;
    host_stat->st_gid = n_gid;
}

static void normalize_statx_if_needed(struct kbox_supervisor_ctx *ctx,
                                      const char *path,
                                      uint8_t *statx_buf)
{
    if (!ctx->normalize)
        return;

    uint32_t n_mode, n_uid, n_gid;
    if (!kbox_normalized_permissions(path, &n_mode, &n_uid, &n_gid))
        return;

    uint16_t mode_le = (uint16_t) n_mode;
    memcpy(&statx_buf[STATX_MODE_OFFSET], &mode_le, 2);
    memcpy(&statx_buf[STATX_UID_OFFSET], &n_uid, 4);
    memcpy(&statx_buf[STATX_GID_OFFSET], &n_gid, 4);
}

static void invalidate_path_shadow_cache(struct kbox_supervisor_ctx *ctx)
{
    size_t i;

    if (!ctx)
        return;
    for (i = 0; i < KBOX_PATH_SHADOW_CACHE_MAX; i++) {
        if (ctx->path_shadow_cache[i].valid &&
            ctx->path_shadow_cache[i].memfd >= 0) {
            close(ctx->path_shadow_cache[i].memfd);
        }
        memset(&ctx->path_shadow_cache[i], 0,
               sizeof(ctx->path_shadow_cache[i]));
        ctx->path_shadow_cache[i].memfd = -1;
    }
    invalidate_translated_path_cache(ctx);
}

static struct kbox_path_shadow_cache_entry *find_path_shadow_cache(
    struct kbox_supervisor_ctx *ctx,
    const char *translated)
{
    size_t i;

    if (!ctx || !translated)
        return NULL;
    for (i = 0; i < KBOX_PATH_SHADOW_CACHE_MAX; i++) {
        struct kbox_path_shadow_cache_entry *entry = &ctx->path_shadow_cache[i];
        if (entry->valid && strcmp(entry->path, translated) == 0)
            return entry;
    }
    return NULL;
}

static struct kbox_path_shadow_cache_entry *reserve_path_shadow_cache_slot(
    struct kbox_supervisor_ctx *ctx,
    const char *translated)
{
    size_t i;
    struct kbox_path_shadow_cache_entry *entry;

    entry = find_path_shadow_cache(ctx, translated);
    if (entry)
        return entry;

    for (i = 0; i < KBOX_PATH_SHADOW_CACHE_MAX; i++) {
        entry = &ctx->path_shadow_cache[i];
        if (!entry->valid)
            return entry;
    }

    entry = &ctx->path_shadow_cache[0];
    if (entry->memfd >= 0)
        close(entry->memfd);
    memset(entry, 0, sizeof(*entry));
    entry->memfd = -1;
    return entry;
}

static int ensure_path_shadow_cache(struct kbox_supervisor_ctx *ctx,
                                    const char *translated)
{
    struct kbox_path_shadow_cache_entry *entry;
    struct stat host_stat;
    int host_fd;

    if (!ctx || !translated || translated[0] == '\0' ||
        ctx->active_writeback_shadows > 0 ||
        kbox_is_lkl_virtual_path(translated) ||
        kbox_is_tty_like_path(translated))
        return 0;

    entry = find_path_shadow_cache(ctx, translated);
    if (entry)
        return 1;

    host_fd = open(translated, O_RDONLY | O_CLOEXEC);
    if (host_fd < 0)
        return 0;

    if (fstat(host_fd, &host_stat) < 0) {
        close(host_fd);
        return 0;
    }
    if (!S_ISREG(host_stat.st_mode)) {
        close(host_fd);
        return 0;
    }
    normalize_host_stat_if_needed(ctx, translated, &host_stat);

    entry = reserve_path_shadow_cache_slot(ctx, translated);
    if (!entry) {
        close(host_fd);
        return 0;
    }

    entry->valid = 1;
    entry->memfd = host_fd;
    strncpy(entry->path, translated, sizeof(entry->path) - 1);
    entry->path[sizeof(entry->path) - 1] = '\0';
    entry->host_stat = host_stat;
    return 1;
}

static int try_cached_shadow_open_dispatch(
    struct kbox_supervisor_ctx *ctx,
    const struct kbox_syscall_request *req,
    long flags,
    const char *translated,
    struct kbox_dispatch *out)
{
    struct kbox_path_shadow_cache_entry *entry;
    int injected;
    int dup_fd;
    long fast_fd;

    if (!ctx || !req || !translated || !out)
        return 0;
    if ((flags & O_ACCMODE) != O_RDONLY)
        return 0;
    if (flags & ~(O_RDONLY | O_CLOEXEC))
        return 0;
    if (!ensure_path_shadow_cache(ctx, translated))
        return 0;

    entry = find_path_shadow_cache(ctx, translated);
    if (!entry || entry->memfd < 0)
        return 0;

    dup_fd = reopen_cached_shadow_fd(ctx, entry);
    if (dup_fd < 0)
        return 0;

    fast_fd = next_hostonly_fd_hint(ctx);
    if (fast_fd < 0) {
        close(dup_fd);
        return 0;
    }
    injected = request_addfd_at(ctx, req, dup_fd, (int) fast_fd,
                                (flags & O_CLOEXEC) ? O_CLOEXEC : 0);
    if (injected < 0) {
        fast_fd = allocate_passthrough_hostonly_fd(ctx);
        if (fast_fd < 0) {
            close(dup_fd);
            return 0;
        }
        injected = request_addfd_at(ctx, req, dup_fd, (int) fast_fd,
                                    (flags & O_CLOEXEC) ? O_CLOEXEC : 0);
    }
    close(dup_fd);
    if (injected < 0)
        return 0;
    ctx->fd_table->next_hostonly_fd = fast_fd;

    *out = kbox_dispatch_value((int64_t) fast_fd);
    return 1;
}

static int try_cached_shadow_stat_dispatch(struct kbox_supervisor_ctx *ctx,
                                           const char *translated,
                                           uint64_t remote_stat,
                                           pid_t pid)
{
    struct kbox_path_shadow_cache_entry *entry;

    if (!ctx || !translated || remote_stat == 0)
        return 0;
    if (!ensure_path_shadow_cache(ctx, translated))
        return 0;

    entry = find_path_shadow_cache(ctx, translated);
    if (!entry)
        return 0;

    return guest_mem_write_small_metadata(ctx, pid, remote_stat,
                                          &entry->host_stat,
                                          sizeof(entry->host_stat)) == 0;
}

static void note_shadow_writeback_open(struct kbox_supervisor_ctx *ctx,
                                       struct kbox_fd_entry *entry)
{
    if (!ctx || !entry || entry->shadow_writeback)
        return;
    entry->shadow_writeback = 1;
    ctx->active_writeback_shadows++;
    invalidate_path_shadow_cache(ctx);
}

static void note_shadow_writeback_close(struct kbox_supervisor_ctx *ctx,
                                        struct kbox_fd_entry *entry)
{
    if (!ctx || !entry || !entry->shadow_writeback)
        return;
    entry->shadow_writeback = 0;
    if (ctx->active_writeback_shadows > 0)
        ctx->active_writeback_shadows--;
}

static int try_writeback_shadow_open(struct kbox_supervisor_ctx *ctx,
                                     const struct kbox_syscall_request *req,
                                     long lkl_fd,
                                     long flags,
                                     const char *translated,
                                     struct kbox_dispatch *out)
{
    struct kbox_fd_entry *entry;
    int memfd;
    int injected;
    long fast_fd;

    if (!ctx || !req || !out || lkl_fd < 0 || !translated)
        return 0;
    if ((flags & O_ACCMODE) == O_RDONLY)
        return 0;
    if (kbox_is_lkl_virtual_path(translated) ||
        kbox_is_tty_like_path(translated))
        return 0;

    memfd = kbox_shadow_create(ctx->sysnrs, lkl_fd);
    if (memfd < 0)
        return 0;
    /* Do NOT seal: this shadow is for a writable FD; the tracee needs
     * write access.  Only read-only shadows (ensure_same_fd_shadow) are
     * sealed.
     */

    fast_fd = kbox_fd_table_insert_fast(ctx->fd_table, lkl_fd, 0);
    if (fast_fd < 0) {
        close(memfd);
        return 0;
    }

    injected = request_addfd_at(ctx, req, memfd, (int) fast_fd,
                                (flags & O_CLOEXEC) ? O_CLOEXEC : 0);
    if (injected < 0) {
        kbox_fd_table_remove(ctx->fd_table, fast_fd);
        close(memfd);
        return 0;
    }

    entry = fd_table_entry(ctx->fd_table, fast_fd);
    if (!entry) {
        kbox_fd_table_remove(ctx->fd_table, fast_fd);
        close(memfd);
        return 0;
    }

    entry->host_fd = KBOX_FD_HOST_SAME_FD_SHADOW;
    entry->shadow_sp = memfd;
    note_shadow_writeback_open(ctx, entry);
    if (ctx->verbose) {
        fprintf(stderr,
                "kbox: writable shadow promote fd=%ld lkl_fd=%ld path=%s\n",
                fast_fd, lkl_fd, translated);
    }
    *out = kbox_dispatch_value((int64_t) fast_fd);
    return 1;
}

typedef long (*kbox_getdents_fn)(const struct kbox_sysnrs *sysnrs,
                                 long fd,
                                 void *buf,
                                 long count);

static struct kbox_dispatch forward_getdents_common(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    kbox_getdents_fn getdents_fn)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    uint64_t remote_dirp = kbox_syscall_request_arg(req, 1);
    int64_t count_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    size_t count, n;
    uint8_t *buf;
    long ret;
    int wrc;

    if (lkl_fd < 0)
        return kbox_dispatch_continue();
    if (count_raw < 0)
        return kbox_dispatch_errno(EINVAL);

    count = (size_t) count_raw;
    if (count == 0)
        return kbox_dispatch_value(0);
    if (remote_dirp == 0)
        return kbox_dispatch_errno(EFAULT);
    if (count > KBOX_IO_CHUNK_LEN)
        count = KBOX_IO_CHUNK_LEN;

    buf = dispatch_scratch;

    ret = getdents_fn(ctx->sysnrs, lkl_fd, buf, (long) count);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    n = (size_t) ret;
    if (n > count)
        return kbox_dispatch_errno(EIO);

    wrc = guest_mem_write(ctx, kbox_syscall_request_pid(req), remote_dirp, buf,
                          n);
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);
    return kbox_dispatch_value((int64_t) n);
}

/* forward_openat. */

static struct kbox_dispatch forward_openat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    int rc = translate_request_at_path(req, ctx, 0, 1, translated,
                                       sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long flags =
        host_to_lkl_open_flags(to_c_long_arg(kbox_syscall_request_arg(req, 2)));
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 3));

    if (kbox_is_lkl_virtual_path(translated))
        return kbox_dispatch_continue();
    if (kbox_is_tty_like_path(translated))
        return kbox_dispatch_continue();

    if (should_continue_for_dirfd(lkl_dirfd))
        return kbox_dispatch_continue();

    {
        struct kbox_dispatch cached_dispatch;
        if (try_cached_shadow_open_dispatch(ctx, req, flags, translated,
                                            &cached_dispatch))
            return cached_dispatch;
    }

    long ret = kbox_lkl_openat(ctx->sysnrs, lkl_dirfd, translated, flags, mode);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));
    if ((flags & O_ACCMODE) != O_RDONLY || (flags & O_TRUNC))
        invalidate_path_shadow_cache(ctx);
    return finish_open_dispatch(ctx, req, ret, flags, translated);
}

/* forward_openat2. */

static struct kbox_dispatch forward_openat2(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    int rc = translate_request_at_path(req, ctx, 0, 1, translated,
                                       sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    struct kbox_open_how how;
    rc = guest_mem_read_open_how(ctx, kbox_syscall_request_pid(req),
                                 kbox_syscall_request_arg(req, 2),
                                 kbox_syscall_request_arg(req, 3), &how);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);
    how.flags = (uint64_t) host_to_lkl_open_flags((long) how.flags);

    if (kbox_is_lkl_virtual_path(translated))
        return kbox_dispatch_continue();
    if (kbox_is_tty_like_path(translated))
        return kbox_dispatch_continue();

    if (should_continue_for_dirfd(lkl_dirfd))
        return kbox_dispatch_continue();

    if (((long) how.flags & O_ACCMODE) == O_RDONLY) {
        struct kbox_dispatch cached_dispatch;
        if (try_cached_shadow_open_dispatch(ctx, req, (long) how.flags,
                                            translated, &cached_dispatch)) {
            return cached_dispatch;
        }
    }

    long ret = kbox_lkl_openat2(ctx->sysnrs, lkl_dirfd, translated, &how,
                                (long) sizeof(how));
    if (ret == -ENOSYS) {
        if (how.resolve != 0)
            return kbox_dispatch_errno(EOPNOTSUPP);
        ret = kbox_lkl_openat(ctx->sysnrs, lkl_dirfd, translated,
                              (long) how.flags, (long) how.mode);
    }
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));
    if (((long) how.flags & O_ACCMODE) != O_RDONLY ||
        ((long) how.flags & O_TRUNC)) {
        invalidate_path_shadow_cache(ctx);
    }
    return finish_open_dispatch(ctx, req, ret, (long) how.flags, translated);
}

/* forward_open_legacy (x86_64 open(2), nr=2). */

static struct kbox_dispatch forward_open_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    int rc = translate_request_path(req, ctx, 0, ctx->host_root, translated,
                                    sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long flags =
        host_to_lkl_open_flags(to_c_long_arg(kbox_syscall_request_arg(req, 1)));
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 2));

    if (kbox_is_lkl_virtual_path(translated))
        return kbox_dispatch_continue();
    if (kbox_is_tty_like_path(translated))
        return kbox_dispatch_continue();

    {
        struct kbox_dispatch cached_dispatch;
        if (try_cached_shadow_open_dispatch(ctx, req, flags, translated,
                                            &cached_dispatch))
            return cached_dispatch;
    }

    long ret =
        kbox_lkl_openat(ctx->sysnrs, AT_FDCWD_LINUX, translated, flags, mode);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));
    if ((flags & O_ACCMODE) != O_RDONLY || (flags & O_TRUNC))
        invalidate_path_shadow_cache(ctx);
    return finish_open_dispatch(ctx, req, ret, flags, translated);
}

static int sync_shadow_writeback(struct kbox_supervisor_ctx *ctx,
                                 struct kbox_fd_entry *entry)
{
    struct stat st;
    uint8_t *buf = NULL;
    off_t off = 0;

    if (!ctx || !entry || !entry->shadow_writeback || entry->shadow_sp < 0 ||
        entry->lkl_fd < 0)
        return 0;

    if (fstat(entry->shadow_sp, &st) < 0)
        return -errno;
    if (kbox_lkl_ftruncate(ctx->sysnrs, entry->lkl_fd, (long) st.st_size) < 0)
        return -EIO;
    if (lseek(entry->shadow_sp, 0, SEEK_SET) < 0)
        return -errno;

    buf = dispatch_scratch;

    while (off < st.st_size) {
        size_t chunk = KBOX_IO_CHUNK_LEN;
        ssize_t rd;
        long wr;

        if ((off_t) chunk > st.st_size - off)
            chunk = (size_t) (st.st_size - off);
        rd = read(entry->shadow_sp, buf, chunk);
        if (rd < 0)
            return -errno;
        if (rd == 0)
            break;
        wr = kbox_lkl_pwrite64(ctx->sysnrs, entry->lkl_fd, buf, (long) rd,
                               (long) off);
        if (wr < 0)
            return (int) wr;
        off += rd;
    }

    return 0;
}

/* forward_close. */

static struct kbox_dispatch forward_close(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);
    int same_fd_shadow = entry && entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW;

    if (lkl_fd >= 0)
        invalidate_stat_cache_fd(ctx, lkl_fd);

    if (entry && entry->lkl_fd == KBOX_LKL_FD_SHADOW_ONLY &&
        entry->shadow_sp >= 0) {
        kbox_fd_table_remove(ctx->fd_table, fd);
        return kbox_dispatch_continue();
    }

    if (lkl_fd >= 0) {
        if (same_fd_shadow) {
            if (entry && entry->shadow_writeback)
                (void) sync_shadow_writeback(ctx, entry);
            note_shadow_writeback_close(ctx, entry);
            lkl_close_and_invalidate(ctx, lkl_fd);
            kbox_fd_table_remove(ctx->fd_table, fd);
            return kbox_dispatch_continue();
        }

        long ret = lkl_close_and_invalidate(ctx, lkl_fd);
        if (ret < 0 && fd >= KBOX_FD_BASE)
            return kbox_dispatch_errno((int) (-ret));
        kbox_fd_table_remove(ctx->fd_table, fd);

        /* Low FD redirect (from dup2): close the LKL side above,
         * then CONTINUE so the host kernel also closes its copy of
         * this FD number.
         */
        if (fd < KBOX_LOW_FD_MAX)
            return kbox_dispatch_continue();

        return kbox_dispatch_value(0);
    }

    /* Not a virtual FD.  Check if this is a host FD that was injected
     * as shadow (the tracee closes it by the host number).  If so,
     * close the LKL side and let the host kernel close the host FD
     * via CONTINUE.
     */
    long vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, fd);
    if (vfd >= 0) {
        struct kbox_fd_entry *shadow_entry = fd_table_entry(ctx->fd_table, vfd);
        long lkl = kbox_fd_table_get_lkl(ctx->fd_table, vfd);

        if (shadow_entry && shadow_entry->shadow_writeback)
            (void) sync_shadow_writeback(ctx, shadow_entry);
        note_shadow_writeback_close(ctx, shadow_entry);
        if (lkl >= 0)
            invalidate_stat_cache_fd(ctx, lkl);
        kbox_fd_table_remove(ctx->fd_table, vfd);

        if (lkl >= 0) {
            /* Only close the LKL socket and deregister from the
             * event loop if no other fd_table entry references the
             * same lkl_fd (handles dup'd shadow sockets).
             */
            int still_ref = 0;
            for (long i = 0; i < KBOX_FD_TABLE_MAX && !still_ref; i++) {
                if (ctx->fd_table->entries[i].lkl_fd == lkl)
                    still_ref = 1;
            }
            for (long i = 0; i < KBOX_LOW_FD_MAX && !still_ref; i++) {
                if (ctx->fd_table->low_fds[i].lkl_fd == lkl)
                    still_ref = 1;
            }
            if (!still_ref) {
                kbox_net_deregister_socket((int) lkl);
                lkl_close_and_invalidate(ctx, lkl);
            }
        }
        return kbox_dispatch_continue();
    }

    return kbox_dispatch_continue();
}

/* forward_read_like (read and pread64). */

static struct kbox_dispatch forward_read_like(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    int is_pread)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    if (lkl_fd < 0)
        return kbox_dispatch_continue();
    {
        struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);
        if (entry && entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW)
            return kbox_dispatch_continue();
    }
    {
        int shadow_rc = ensure_same_fd_shadow(ctx, req, fd, lkl_fd);
        if (shadow_rc > 0) {
            struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);
            if (entry && entry->host_fd == KBOX_FD_LOCAL_ONLY_SHADOW) {
                return forward_local_shadow_read_like(req, ctx, entry, lkl_fd,
                                                      is_pread);
            }
            return kbox_dispatch_continue();
        }
    }

    uint64_t remote_buf = kbox_syscall_request_arg(req, 1);
    int64_t count_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    if (count_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t count = (size_t) count_raw;

    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);
    if (count == 0)
        return kbox_dispatch_value(0);

    pid_t pid = kbox_syscall_request_pid(req);
    size_t max_count = 1024 * 1024;
    if (count > max_count)
        count = max_count;

    size_t total = 0;
    uint8_t *scratch = dispatch_scratch;

    while (total < count) {
        size_t chunk_len = KBOX_IO_CHUNK_LEN;
        if (chunk_len > count - total)
            chunk_len = count - total;

        long ret;
        if (is_pread) {
            long offset = to_c_long_arg(kbox_syscall_request_arg(req, 3));
            ret = kbox_lkl_pread64(ctx->sysnrs, lkl_fd, scratch,
                                   (long) chunk_len, offset + (long) total);
        } else {
            ret = kbox_lkl_read(ctx->sysnrs, lkl_fd, scratch, (long) chunk_len);
        }

        if (ret < 0) {
            if (total == 0) {
                return kbox_dispatch_errno((int) (-ret));
            }
            break;
        }

        size_t n = (size_t) ret;
        if (n == 0)
            break;

        uint64_t remote = remote_buf + total;
        if (ctx->verbose) {
            fprintf(
                stderr,
                "kbox: %s fd=%ld lkl_fd=%ld remote=0x%llx chunk=%zu ret=%ld\n",
                is_pread ? "pread64" : "read", fd, lkl_fd,
                (unsigned long long) remote, chunk_len, ret);
        }
        int wrc = guest_mem_write(ctx, pid, remote, scratch, n);
        if (wrc < 0) {
            return kbox_dispatch_errno(-wrc);
        }

        total += n;
        if (n < chunk_len)
            break;
    }

    return kbox_dispatch_value((int64_t) total);
}

/* forward_write. */

static struct kbox_dispatch forward_write(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);

    if (lkl_fd < 0)
        return kbox_dispatch_continue();
    if (entry && entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW)
        return kbox_dispatch_continue();

    invalidate_stat_cache_fd(ctx, lkl_fd);

    int mirror_host = kbox_fd_table_mirror_tty(ctx->fd_table, fd);

    uint64_t remote_buf = kbox_syscall_request_arg(req, 1);
    int64_t count_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    if (count_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t count = (size_t) count_raw;

    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);
    if (count == 0)
        return kbox_dispatch_value(0);

    pid_t pid = kbox_syscall_request_pid(req);
    size_t max_count = 1024 * 1024;
    if (count > max_count)
        count = max_count;

    size_t total = 0;
    uint8_t *scratch = dispatch_scratch;

    while (total < count) {
        size_t chunk_len = KBOX_IO_CHUNK_LEN;
        if (chunk_len > count - total)
            chunk_len = count - total;

        uint64_t remote = remote_buf + total;
        int rrc = guest_mem_read(ctx, pid, remote, scratch, chunk_len);
        if (rrc < 0) {
            if (total > 0)
                break;
            return kbox_dispatch_errno(-rrc);
        }

        long ret =
            kbox_lkl_write(ctx->sysnrs, lkl_fd, scratch, (long) chunk_len);
        if (ret < 0) {
            if (total == 0) {
                return kbox_dispatch_errno((int) (-ret));
            }
            break;
        }

        size_t n = (size_t) ret;

        /* Mirror to host stdout if this is a TTY fd.  The guest fd
         * is a virtual number (4096+) that does not exist on the
         * host side, so we write to stdout instead.
         */
        if (mirror_host && n > 0) {
            (void) write(STDOUT_FILENO, scratch, n);
        }

        total += n;
        if (n < chunk_len)
            break;
    }

    if (total > 0)
        invalidate_path_shadow_cache(ctx);
    return kbox_dispatch_value((int64_t) total);
}

/* forward_sendfile. */

/* Emulate sendfile(out_fd, in_fd, *offset, count).
 *
 * If both FDs are host-visible (shadow memfds, stdio, or other host FDs
 * not in the virtual table), let the host kernel handle it via CONTINUE.
 * Otherwise, emulate via LKL read + host/LKL write.
 *
 * busybox cat uses sendfile and some builds loop on ENOSYS instead of
 * falling back to read+write, so returning ENOSYS is not viable.
 */
static struct kbox_dispatch forward_sendfile(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long out_fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long in_fd = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    uint64_t offset_ptr = kbox_syscall_request_arg(req, 2);
    int64_t count_raw = to_c_long_arg(kbox_syscall_request_arg(req, 3));

    long in_lkl = kbox_fd_table_get_lkl(ctx->fd_table, in_fd);
    long out_lkl = kbox_fd_table_get_lkl(ctx->fd_table, out_fd);

    /* Resolve shadow FDs: if in_fd is a host FD injected via ADDFD (shadow
     * memfd), find_by_host_fd locates the virtual entry that holds the LKL
     * FD for the same file.
     */
    if (in_lkl < 0) {
        long vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, in_fd);
        if (vfd >= 0)
            in_lkl = kbox_fd_table_get_lkl(ctx->fd_table, vfd);
    }
    if (out_lkl < 0) {
        long vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, out_fd);
        if (vfd >= 0)
            out_lkl = kbox_fd_table_get_lkl(ctx->fd_table, vfd);
    }

    /* Both FDs are host-visible (shadow memfds, stdio, pipes, etc.) and
     * neither has LKL backing.  The host kernel handles sendfile.
     */
    if (in_lkl < 0 && out_lkl < 0)
        return kbox_dispatch_continue();

    /* At least one FD is virtual/LKL-backed: emulate via read + write.
     * Source must have an LKL FD for emulation.
     */
    if (in_lkl < 0)
        return kbox_dispatch_errno(EBADF);

    if (count_raw <= 0)
        return kbox_dispatch_value(0);
    size_t count = (size_t) count_raw;
    if (count > 1024 * 1024)
        count = 1024 * 1024;

    /* Read optional offset from tracee memory. */
    pid_t pid = kbox_syscall_request_pid(req);
    off_t offset = 0;
    int has_offset = (offset_ptr != 0);
    if (has_offset) {
        int rc = guest_mem_read(ctx, pid, offset_ptr, &offset, sizeof(offset));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
    }

    uint8_t *scratch = dispatch_scratch;

    size_t total = 0;

    while (total < count) {
        size_t chunk = KBOX_IO_CHUNK_LEN;
        if (chunk > count - total)
            chunk = count - total;

        /* Read from source (LKL fd). */
        long nr;
        if (has_offset)
            nr = kbox_lkl_pread64(ctx->sysnrs, in_lkl, scratch, (long) chunk,
                                  offset + (long) total);
        else
            nr = kbox_lkl_read(ctx->sysnrs, in_lkl, scratch, (long) chunk);

        if (nr < 0) {
            if (total == 0) {
                return kbox_dispatch_errno((int) (-nr));
            }
            break;
        }
        if (nr == 0)
            break;

        size_t n = (size_t) nr;

        /* Write to destination. */
        if (out_lkl >= 0) {
            long wr = kbox_lkl_write(ctx->sysnrs, out_lkl, scratch, (long) n);
            if (wr < 0) {
                if (total == 0) {
                    return kbox_dispatch_errno((int) (-wr));
                }
                break;
            }
        } else {
            /* Destination is a host FD (e.g. stdout).  The supervisor
             * shares the FD table with the tracee (from fork), so write()
             * goes to the same file description.
             */
            ssize_t wr = write((int) out_fd, scratch, n);
            if (wr < 0) {
                if (total == 0) {
                    return kbox_dispatch_errno(errno);
                }
                break;
            }
        }

        total += n;
        if (n < chunk)
            break;
    }

    /* Update offset in tracee memory if provided. */
    if (has_offset && total > 0) {
        off_t new_off = offset + (off_t) total;
        guest_mem_write(ctx, pid, offset_ptr, &new_off, sizeof(new_off));
    }

    return kbox_dispatch_value((int64_t) total);
}

/* forward_lseek. */

static struct kbox_dispatch forward_lseek(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd < 0)
        return kbox_dispatch_continue();
    {
        struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);
        if (entry && entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW)
            return kbox_dispatch_continue();
    }
    {
        int shadow_rc = ensure_same_fd_shadow(ctx, req, fd, lkl_fd);
        if (shadow_rc > 0) {
            struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);
            if (entry && entry->host_fd == KBOX_FD_LOCAL_ONLY_SHADOW)
                return forward_local_shadow_lseek(req, ctx, entry, lkl_fd);
            return kbox_dispatch_continue();
        }
    }

    long off = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long whence = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long ret = kbox_lkl_lseek(ctx->sysnrs, lkl_fd, off, whence);
    if (ctx->verbose) {
        fprintf(stderr,
                "kbox: lseek fd=%ld lkl_fd=%ld off=%ld whence=%ld ret=%ld\n",
                fd, lkl_fd, off, whence, ret);
    }
    return kbox_dispatch_from_lkl(ret);
}

/* forward_fcntl. */

static struct kbox_dispatch forward_fcntl(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd < 0) {
        /* Shadow socket: handle F_DUPFD* and F_SETFL. */
        long svfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, fd);
        if (svfd >= 0) {
            long scmd = to_c_long_arg(kbox_syscall_request_arg(req, 1));
            if (scmd == F_DUPFD || scmd == F_DUPFD_CLOEXEC) {
                long minfd = to_c_long_arg(kbox_syscall_request_arg(req, 2));
                /* When minfd > 0, skip ADDFD (can't honor the minimum)
                 * and let CONTINUE handle it correctly.  The dup is
                 * untracked but no FD leaks.
                 */
                struct kbox_fd_entry *orig = NULL;
                if (minfd > 0)
                    goto fcntl_continue;
                if (svfd >= KBOX_FD_BASE)
                    orig = &ctx->fd_table->entries[svfd - KBOX_FD_BASE];
                else if (svfd < KBOX_LOW_FD_MAX)
                    orig = &ctx->fd_table->low_fds[svfd];
                if (orig && orig->shadow_sp >= 0) {
                    uint32_t af = (scmd == F_DUPFD_CLOEXEC) ? O_CLOEXEC : 0;
                    int nh = request_addfd(ctx, req, orig->shadow_sp, af);
                    if (nh >= 0) {
                        long nv = kbox_fd_table_insert(ctx->fd_table,
                                                       orig->lkl_fd, 0);
                        if (nv < 0)
                            return kbox_dispatch_errno(EMFILE);
                        kbox_fd_table_set_host_fd(ctx->fd_table, nv, nh);
                        int ns = dup(orig->shadow_sp);
                        if (ns >= 0) {
                            struct kbox_fd_entry *ne = NULL;
                            if (nv >= KBOX_FD_BASE)
                                ne = &ctx->fd_table->entries[nv - KBOX_FD_BASE];
                            else if (nv < KBOX_LOW_FD_MAX)
                                ne = &ctx->fd_table->low_fds[nv];
                            if (ne) {
                                ne->shadow_sp = ns;
                                if (scmd == F_DUPFD_CLOEXEC)
                                    ne->cloexec = 1;
                            } else {
                                close(ns);
                            }
                        }
                        return kbox_dispatch_value((int64_t) nh);
                    }
                }
            }
            if (scmd == F_SETFL) {
                long sarg = to_c_long_arg(kbox_syscall_request_arg(req, 2));
                long slkl = kbox_fd_table_get_lkl(ctx->fd_table, svfd);
                if (slkl >= 0)
                    kbox_lkl_fcntl(ctx->sysnrs, slkl, F_SETFL, sarg);
            }
            if (scmd == F_SETFD) {
                /* Keep fd-table cloexec in sync with host kernel. */
                long sarg = to_c_long_arg(kbox_syscall_request_arg(req, 2));
                kbox_fd_table_set_cloexec(ctx->fd_table, svfd,
                                          (sarg & FD_CLOEXEC) ? 1 : 0);
            }
        }
    fcntl_continue:
        return kbox_dispatch_continue();
    }

    long cmd = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long arg = to_c_long_arg(kbox_syscall_request_arg(req, 2));

    if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC) {
        long ret = kbox_lkl_fcntl(ctx->sysnrs, lkl_fd, cmd, arg);
        if (ret < 0)
            return kbox_dispatch_errno((int) (-ret));

        int mirror = kbox_fd_table_mirror_tty(ctx->fd_table, fd);
        long new_vfd = kbox_fd_table_insert(ctx->fd_table, ret, mirror);
        if (new_vfd < 0) {
            lkl_close_and_invalidate(ctx, ret);
            return kbox_dispatch_errno(EMFILE);
        }
        if (cmd == F_DUPFD_CLOEXEC)
            kbox_fd_table_set_cloexec(ctx->fd_table, new_vfd, 1);
        return kbox_dispatch_value((int64_t) new_vfd);
    }

    /* F_SETFL: translate host open flags to LKL before forwarding. */
    if (cmd == F_SETFL)
        arg = host_to_lkl_open_flags(arg);

    long ret = kbox_lkl_fcntl(ctx->sysnrs, lkl_fd, cmd, arg);

    /* F_GETFL: translate LKL open flags back to host before returning. */
    if (cmd == F_GETFL && ret >= 0)
        ret = lkl_to_host_open_flags(ret);

    return kbox_dispatch_from_lkl(ret);
}

/* forward_dup. */

static struct kbox_dispatch forward_dup(const struct kbox_syscall_request *req,
                                        struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd < 0) {
        /* Check for shadow socket (tracee holds host_fd from ADDFD). */
        long orig_vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, fd);
        if (orig_vfd < 0)
            return kbox_dispatch_continue();

        /* Shadow socket dup: inject a new copy of the socketpair end into
         * the tracee and track the new host_fd.
         */
        struct kbox_fd_entry *orig = NULL;
        if (orig_vfd >= KBOX_FD_BASE)
            orig = &ctx->fd_table->entries[orig_vfd - KBOX_FD_BASE];
        else if (orig_vfd < KBOX_LOW_FD_MAX)
            orig = &ctx->fd_table->low_fds[orig_vfd];
        if (!orig || orig->shadow_sp < 0)
            return kbox_dispatch_continue();

        long orig_lkl = orig->lkl_fd;
        int new_host = request_addfd(ctx, req, orig->shadow_sp, 0);
        if (new_host < 0)
            return kbox_dispatch_errno(-new_host);

        long new_vfd = kbox_fd_table_insert(ctx->fd_table, orig_lkl, 0);
        if (new_vfd < 0) {
            /* Can't track the FD; return error.  The tracee already has
             * the FD via ADDFD which we can't revoke, but returning
             * EMFILE tells the caller dup failed so it won't use it.
             */
            return kbox_dispatch_errno(EMFILE);
        }
        kbox_fd_table_set_host_fd(ctx->fd_table, new_vfd, new_host);

        /* Propagate shadow_sp so chained dups work. */
        int new_sp = dup(orig->shadow_sp);
        if (new_sp >= 0) {
            struct kbox_fd_entry *ne = NULL;
            if (new_vfd >= KBOX_FD_BASE)
                ne = &ctx->fd_table->entries[new_vfd - KBOX_FD_BASE];
            else if (new_vfd < KBOX_LOW_FD_MAX)
                ne = &ctx->fd_table->low_fds[new_vfd];
            if (ne)
                ne->shadow_sp = new_sp;
            else
                close(new_sp);
        }
        return kbox_dispatch_value((int64_t) new_host);
    }

    long ret = kbox_lkl_dup(ctx->sysnrs, lkl_fd);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    int mirror = kbox_fd_table_mirror_tty(ctx->fd_table, fd);
    long new_vfd = kbox_fd_table_insert(ctx->fd_table, ret, mirror);
    if (new_vfd < 0) {
        lkl_close_and_invalidate(ctx, ret);
        return kbox_dispatch_errno(EMFILE);
    }
    return kbox_dispatch_value((int64_t) new_vfd);
}

/* forward_dup2. */

static struct kbox_dispatch forward_dup2(const struct kbox_syscall_request *req,
                                         struct kbox_supervisor_ctx *ctx)
{
    long oldfd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long newfd = to_c_long_arg(kbox_syscall_request_arg(req, 1));

    long lkl_old = kbox_fd_table_get_lkl(ctx->fd_table, oldfd);
    if (lkl_old < 0) {
        /* Shadow socket dup2: dup2(fd, fd) must return fd unchanged. */
        if (oldfd == newfd)
            return kbox_dispatch_value((int64_t) newfd);

        long orig_vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, oldfd);
        if (orig_vfd >= 0) {
            struct kbox_fd_entry *orig = NULL;
            if (orig_vfd >= KBOX_FD_BASE)
                orig = &ctx->fd_table->entries[orig_vfd - KBOX_FD_BASE];
            else if (orig_vfd < KBOX_LOW_FD_MAX)
                orig = &ctx->fd_table->low_fds[orig_vfd];
            if (orig && orig->shadow_sp >= 0) {
                int new_host =
                    request_addfd_at(ctx, req, orig->shadow_sp, (int) newfd, 0);
                if (new_host >= 0) {
                    /* Remove any stale mapping at newfd (virtual or shadow). */
                    long stale = kbox_fd_table_get_lkl(ctx->fd_table, newfd);
                    if (stale >= 0) {
                        lkl_close_and_invalidate(ctx, stale);
                        kbox_fd_table_remove(ctx->fd_table, newfd);
                    } else {
                        long sv =
                            kbox_fd_table_find_by_host_fd(ctx->fd_table, newfd);
                        if (sv >= 0) {
                            long sl = kbox_fd_table_get_lkl(ctx->fd_table, sv);
                            kbox_fd_table_remove(ctx->fd_table, sv);
                            if (sl >= 0) {
                                int ref = 0;
                                for (long j = 0; j < KBOX_FD_TABLE_MAX; j++)
                                    if (ctx->fd_table->entries[j].lkl_fd == sl)
                                        ref = 1;
                                for (long j = 0; j < KBOX_LOW_FD_MAX && !ref;
                                     j++)
                                    if (ctx->fd_table->low_fds[j].lkl_fd == sl)
                                        ref = 1;
                                if (!ref) {
                                    kbox_net_deregister_socket((int) sl);
                                    lkl_close_and_invalidate(ctx, sl);
                                }
                            }
                        }
                    }
                    long nv =
                        kbox_fd_table_insert(ctx->fd_table, orig->lkl_fd, 0);
                    if (nv < 0)
                        return kbox_dispatch_errno(EMFILE);
                    kbox_fd_table_set_host_fd(ctx->fd_table, nv, new_host);
                    int ns = dup(orig->shadow_sp);
                    if (ns >= 0) {
                        struct kbox_fd_entry *ne2 = NULL;
                        if (nv >= KBOX_FD_BASE)
                            ne2 = &ctx->fd_table->entries[nv - KBOX_FD_BASE];
                        else if (nv < KBOX_LOW_FD_MAX)
                            ne2 = &ctx->fd_table->low_fds[nv];
                        if (ne2)
                            ne2->shadow_sp = ns;
                        else
                            close(ns);
                    }
                    return kbox_dispatch_value((int64_t) newfd);
                }
            }
        }
        /* oldfd is a host FD.  If newfd has a stale LKL redirect (from
         * a previous dup2), clean it up before the host kernel overwrites
         * the FD.  Without this, the shell's dup2(saved_stdout, 1) leaves
         * a stale low_fds entry that traps all subsequent writes to FD 1
         * in LKL.
         */
        long stale = kbox_fd_table_get_lkl(ctx->fd_table, newfd);
        if (stale >= 0) {
            lkl_close_and_invalidate(ctx, stale);
            kbox_fd_table_remove(ctx->fd_table, newfd);
        } else {
            long sv = kbox_fd_table_find_by_host_fd(ctx->fd_table, newfd);
            if (sv >= 0) {
                long sl = kbox_fd_table_get_lkl(ctx->fd_table, sv);
                kbox_fd_table_remove(ctx->fd_table, sv);
                if (sl >= 0) {
                    int ref = 0;
                    for (long j = 0; j < KBOX_FD_TABLE_MAX; j++)
                        if (ctx->fd_table->entries[j].lkl_fd == sl)
                            ref = 1;
                    for (long j = 0; j < KBOX_LOW_FD_MAX && !ref; j++)
                        if (ctx->fd_table->low_fds[j].lkl_fd == sl)
                            ref = 1;
                    if (!ref) {
                        kbox_net_deregister_socket((int) sl);
                        lkl_close_and_invalidate(ctx, sl);
                    }
                }
            }
        }
        return kbox_dispatch_continue();
    }

    if (oldfd == newfd)
        return kbox_dispatch_value((int64_t) newfd);

    /* Dup first, then close the old mapping.  This preserves the old newfd
     * if the dup fails (e.g. EMFILE), matching dup2 atomicity semantics.
     */
    long ret = kbox_lkl_dup(ctx->sysnrs, lkl_old);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    long existing = kbox_fd_table_remove(ctx->fd_table, newfd);
    if (existing >= 0)
        lkl_close_and_invalidate(ctx, existing);

    int mirror = kbox_fd_table_mirror_tty(ctx->fd_table, oldfd);
    if (kbox_fd_table_insert_at(ctx->fd_table, newfd, ret, mirror) < 0) {
        lkl_close_and_invalidate(ctx, ret);
        return kbox_dispatch_errno(EBADF);
    }
    return kbox_dispatch_value((int64_t) newfd);
}

/* forward_dup3. */

static struct kbox_dispatch forward_dup3(const struct kbox_syscall_request *req,
                                         struct kbox_supervisor_ctx *ctx)
{
    long oldfd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long newfd = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 2));

    /* dup3 only accepts O_CLOEXEC; reject anything else per POSIX. */
    if (flags & ~((long) O_CLOEXEC))
        return kbox_dispatch_errno(EINVAL);

    long lkl_old = kbox_fd_table_get_lkl(ctx->fd_table, oldfd);
    if (lkl_old < 0) {
        /* Shadow socket dup3: dup3(fd, fd, ...) must return EINVAL. */
        if (oldfd == newfd) {
            if (kbox_fd_table_find_by_host_fd(ctx->fd_table, oldfd) >= 0)
                return kbox_dispatch_errno(EINVAL);
        }

        long orig_vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, oldfd);
        if (orig_vfd >= 0) {
            struct kbox_fd_entry *orig = NULL;
            if (orig_vfd >= KBOX_FD_BASE)
                orig = &ctx->fd_table->entries[orig_vfd - KBOX_FD_BASE];
            else if (orig_vfd < KBOX_LOW_FD_MAX)
                orig = &ctx->fd_table->low_fds[orig_vfd];
            if (orig && orig->shadow_sp >= 0) {
                uint32_t af = (flags & O_CLOEXEC) ? O_CLOEXEC : 0;
                int new_host = request_addfd_at(ctx, req, orig->shadow_sp,
                                                (int) newfd, af);
                if (new_host >= 0) {
                    /* Remove stale mapping at newfd (virtual or shadow). */
                    long stale3 = kbox_fd_table_get_lkl(ctx->fd_table, newfd);
                    if (stale3 >= 0) {
                        lkl_close_and_invalidate(ctx, stale3);
                        kbox_fd_table_remove(ctx->fd_table, newfd);
                    } else {
                        long sv3 =
                            kbox_fd_table_find_by_host_fd(ctx->fd_table, newfd);
                        if (sv3 >= 0) {
                            long sl3 =
                                kbox_fd_table_get_lkl(ctx->fd_table, sv3);
                            kbox_fd_table_remove(ctx->fd_table, sv3);
                            if (sl3 >= 0) {
                                int r3 = 0;
                                for (long j = 0; j < KBOX_FD_TABLE_MAX; j++)
                                    if (ctx->fd_table->entries[j].lkl_fd == sl3)
                                        r3 = 1;
                                for (long j = 0; j < KBOX_LOW_FD_MAX && !r3;
                                     j++)
                                    if (ctx->fd_table->low_fds[j].lkl_fd == sl3)
                                        r3 = 1;
                                if (!r3) {
                                    kbox_net_deregister_socket((int) sl3);
                                    lkl_close_and_invalidate(ctx, sl3);
                                }
                            }
                        }
                    }
                    long nv =
                        kbox_fd_table_insert(ctx->fd_table, orig->lkl_fd, 0);
                    if (nv < 0)
                        return kbox_dispatch_errno(EMFILE);
                    kbox_fd_table_set_host_fd(ctx->fd_table, nv, new_host);
                    int ns3 = dup(orig->shadow_sp);
                    if (ns3 >= 0) {
                        struct kbox_fd_entry *ne3 = NULL;
                        if (nv >= KBOX_FD_BASE)
                            ne3 = &ctx->fd_table->entries[nv - KBOX_FD_BASE];
                        else if (nv < KBOX_LOW_FD_MAX)
                            ne3 = &ctx->fd_table->low_fds[nv];
                        if (ne3) {
                            ne3->shadow_sp = ns3;
                            if (flags & O_CLOEXEC)
                                ne3->cloexec = 1;
                        } else {
                            close(ns3);
                        }
                    }
                    return kbox_dispatch_value((int64_t) newfd);
                }
            }
        }
        /* Same stale-redirect cleanup as forward_dup2. */
        long stale = kbox_fd_table_get_lkl(ctx->fd_table, newfd);
        if (stale >= 0) {
            lkl_close_and_invalidate(ctx, stale);
            kbox_fd_table_remove(ctx->fd_table, newfd);
        } else {
            long sv = kbox_fd_table_find_by_host_fd(ctx->fd_table, newfd);
            if (sv >= 0) {
                long sl = kbox_fd_table_get_lkl(ctx->fd_table, sv);
                kbox_fd_table_remove(ctx->fd_table, sv);
                if (sl >= 0) {
                    int ref = 0;
                    for (long j = 0; j < KBOX_FD_TABLE_MAX; j++)
                        if (ctx->fd_table->entries[j].lkl_fd == sl)
                            ref = 1;
                    for (long j = 0; j < KBOX_LOW_FD_MAX && !ref; j++)
                        if (ctx->fd_table->low_fds[j].lkl_fd == sl)
                            ref = 1;
                    if (!ref) {
                        kbox_net_deregister_socket((int) sl);
                        lkl_close_and_invalidate(ctx, sl);
                    }
                }
            }
        }
        return kbox_dispatch_continue();
    }

    if (oldfd == newfd)
        return kbox_dispatch_errno(EINVAL);

    long ret = kbox_lkl_dup(ctx->sysnrs, lkl_old);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    long existing = kbox_fd_table_remove(ctx->fd_table, newfd);
    if (existing >= 0)
        lkl_close_and_invalidate(ctx, existing);

    int mirror = kbox_fd_table_mirror_tty(ctx->fd_table, oldfd);
    if (kbox_fd_table_insert_at(ctx->fd_table, newfd, ret, mirror) < 0) {
        lkl_close_and_invalidate(ctx, ret);
        return kbox_dispatch_errno(EBADF);
    }
    if (flags & O_CLOEXEC)
        kbox_fd_table_set_cloexec(ctx->fd_table, newfd, 1);
    return kbox_dispatch_value((int64_t) newfd);
}

/* forward_fstat. */

static struct kbox_dispatch forward_fstat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd < 0)
        return kbox_dispatch_continue();
    /* If a shadow already exists (from a prior mmap), let the host handle
     * fstat against the memfd.  Do NOT create a shadow here -- fstat is a
     * metadata query that LKL answers directly without the expensive
     * memfd_create + pread loop.
     */
    {
        struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);
        if (entry && entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW)
            return kbox_dispatch_continue();
        if (entry && entry->host_fd == KBOX_FD_LOCAL_ONLY_SHADOW)
            return forward_local_shadow_fstat(req, ctx, entry);
    }

    uint64_t remote_stat = kbox_syscall_request_arg(req, 1);
    if (remote_stat == 0)
        return kbox_dispatch_errno(EFAULT);

    /* Check the stat cache first to avoid an LKL round-trip. */
#if KBOX_STAT_CACHE_ENABLED
    for (int ci = 0; ci < KBOX_STAT_CACHE_MAX; ci++) {
        if (ctx->stat_cache[ci].lkl_fd == lkl_fd) {
            int wrc = guest_mem_write_small_metadata(
                ctx, kbox_syscall_request_pid(req), remote_stat,
                &ctx->stat_cache[ci].st, sizeof(ctx->stat_cache[ci].st));
            if (wrc < 0)
                return kbox_dispatch_errno(-wrc);
            return kbox_dispatch_value(0);
        }
    }
#endif

    struct kbox_lkl_stat kst;
    memset(&kst, 0, sizeof(kst));
    long ret = kbox_lkl_fstat(ctx->sysnrs, lkl_fd, &kst);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    struct stat host_stat;
    kbox_lkl_stat_to_host(&kst, &host_stat);

    /* Insert into stat cache (overwrite oldest slot via round-robin). */
#if KBOX_STAT_CACHE_ENABLED
    {
        static unsigned stat_cache_rr;
        unsigned slot = stat_cache_rr % KBOX_STAT_CACHE_MAX;
        stat_cache_rr++;
        ctx->stat_cache[slot].lkl_fd = lkl_fd;
        ctx->stat_cache[slot].st = host_stat;
    }
#endif

    int wrc = guest_mem_write_small_metadata(ctx, kbox_syscall_request_pid(req),
                                             remote_stat, &host_stat,
                                             sizeof(host_stat));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

/* forward_newfstatat. */

static struct kbox_dispatch forward_newfstatat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    int rc = translate_request_at_path(req, ctx, 0, 1, translated,
                                       sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);
    if (should_continue_for_dirfd(lkl_dirfd))
        return kbox_dispatch_continue();

    uint64_t remote_stat = kbox_syscall_request_arg(req, 2);
    if (remote_stat == 0)
        return kbox_dispatch_errno(EFAULT);

    if (translated[0] != '\0' &&
        try_cached_shadow_stat_dispatch(ctx, translated, remote_stat,
                                        kbox_syscall_request_pid(req))) {
        return kbox_dispatch_value(0);
    }

    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 3));

    struct kbox_lkl_stat kst;
    memset(&kst, 0, sizeof(kst));

    long ret;
    if (translated[0] == '\0' && (flags & AT_EMPTY_PATH))
        ret = kbox_lkl_fstat(ctx->sysnrs, lkl_dirfd, &kst);
    else
        ret = kbox_lkl_newfstatat(ctx->sysnrs, lkl_dirfd, translated, &kst,
                                  flags);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    struct stat host_stat;
    kbox_lkl_stat_to_host(&kst, &host_stat);
    normalize_host_stat_if_needed(ctx, translated, &host_stat);

    int wrc = guest_mem_write_small_metadata(ctx, kbox_syscall_request_pid(req),
                                             remote_stat, &host_stat,
                                             sizeof(host_stat));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

/* Guest-thread local fast-path.  Handles syscalls that never touch LKL and
 * can be resolved on the calling thread without a service-thread round-trip.
 * Returns 1 if handled (result in *out), 0 if the caller must use the service
 * thread.  Safe to call from the SIGSYS handler or rewrite trampoline context.
 *
 * Three tiers:
 *   1. Pure emulation -- cached constant values (getpid, getppid, gettid).
 *   2. Always-CONTINUE -- host kernel handles the syscall unmodified.
 *   3. Conditional emulation -- e.g. arch_prctl(SET_FS) in trap/rewrite.
 *
 * LKL-touching syscalls (stat, openat, read on LKL FDs, etc.) are NOT
 * handled here; they MUST go through the service thread.
 */
int kbox_dispatch_try_local_fast_path(const struct kbox_host_nrs *h,
                                      int nr,
                                      struct kbox_dispatch *out)
{
    if (!h || !out)
        return 0;

    /* Tier 1: pure emulation. */
    if (nr == h->getpid) {
        *out = kbox_dispatch_value(1);
        return 1;
    }
    if (nr == h->getppid) {
        *out = kbox_dispatch_value(0);
        return 1;
    }
    if (nr == h->gettid) {
        *out = kbox_dispatch_value(1);
        return 1;
    }

    /* Tier 2: always-CONTINUE -- host kernel handles these directly. */
    if (nr == h->brk || nr == h->futex || nr == h->rseq ||
        nr == h->set_tid_address || nr == h->set_robust_list ||
        nr == h->munmap || nr == h->mremap || nr == h->membarrier ||
        nr == h->madvise || nr == h->wait4 || nr == h->waitid ||
        nr == h->exit || nr == h->exit_group || nr == h->rt_sigreturn ||
        nr == h->rt_sigaltstack || nr == h->setitimer || nr == h->getitimer ||
        nr == h->setpgid || nr == h->getpgid || nr == h->getsid ||
        nr == h->setsid || nr == h->fork || nr == h->vfork ||
        nr == h->sched_yield || nr == h->sched_setparam ||
        nr == h->sched_getparam || nr == h->sched_setscheduler ||
        nr == h->sched_getscheduler || nr == h->sched_get_priority_max ||
        nr == h->sched_get_priority_min || nr == h->sched_setaffinity ||
        nr == h->sched_getaffinity || nr == h->getrlimit ||
        nr == h->getrusage || nr == h->epoll_create1 || nr == h->epoll_ctl ||
        nr == h->epoll_wait || nr == h->epoll_pwait || nr == h->ppoll ||
        nr == h->pselect6 || nr == h->poll || nr == h->nanosleep ||
        nr == h->clock_nanosleep || nr == h->timerfd_create ||
        nr == h->timerfd_settime || nr == h->timerfd_gettime ||
        nr == h->eventfd || nr == h->eventfd2 || nr == h->statfs ||
        nr == h->fstatfs || nr == h->sysinfo) {
        *out = kbox_dispatch_continue();
        return 1;
    }

    return 0;
}

/* forward_statx. */

static struct kbox_dispatch forward_statx(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    int rc = translate_request_at_path(req, ctx, 0, 1, translated,
                                       sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);
    if (should_continue_for_dirfd(lkl_dirfd))
        return kbox_dispatch_continue();

    int flags = (int) to_c_long_arg(kbox_syscall_request_arg(req, 2));
    unsigned mask = (unsigned) to_c_long_arg(kbox_syscall_request_arg(req, 3));
    uint64_t remote_statx = kbox_syscall_request_arg(req, 4);
    if (remote_statx == 0)
        return kbox_dispatch_errno(EFAULT);

    uint8_t statx_buf[STATX_BUF_SIZE];
    memset(statx_buf, 0, sizeof(statx_buf));

    long ret = kbox_lkl_statx(ctx->sysnrs, lkl_dirfd, translated, flags, mask,
                              statx_buf);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    normalize_statx_if_needed(ctx, translated, statx_buf);

    int wrc = guest_mem_write(ctx, kbox_syscall_request_pid(req), remote_statx,
                              statx_buf, sizeof(statx_buf));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

/* forward_faccessat / forward_faccessat2. */

static struct kbox_dispatch do_faccessat(const struct kbox_syscall_request *req,
                                         struct kbox_supervisor_ctx *ctx,
                                         long flags)
{
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    int rc = translate_request_at_path(req, ctx, 0, 1, translated,
                                       sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);
    if (should_continue_for_dirfd(lkl_dirfd))
        return kbox_dispatch_continue();

    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long ret =
        kbox_lkl_faccessat2(ctx->sysnrs, lkl_dirfd, translated, mode, flags);
    return kbox_dispatch_from_lkl(ret);
}

static struct kbox_dispatch forward_faccessat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return do_faccessat(req, ctx, 0);
}

static struct kbox_dispatch forward_faccessat2(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return do_faccessat(req, ctx,
                        to_c_long_arg(kbox_syscall_request_arg(req, 3)));
}

/* forward_getdents64. */

static struct kbox_dispatch forward_getdents64(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_getdents_common(req, ctx, kbox_lkl_getdents64);
}

/* forward_getdents (legacy). */

static struct kbox_dispatch forward_getdents(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_getdents_common(req, ctx, kbox_lkl_getdents);
}

/* forward_chdir. */

static struct kbox_dispatch forward_chdir(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    int rc = translate_request_path(req, ctx, 0, ctx->host_root, translated,
                                    sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long ret = kbox_lkl_chdir(ctx->sysnrs, translated);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    invalidate_translated_path_cache(ctx);
    return kbox_dispatch_value(0);
}

/* forward_fchdir. */

static struct kbox_dispatch forward_fchdir(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    long ret = kbox_lkl_fchdir(ctx->sysnrs, lkl_fd);
    if (ret >= 0)
        invalidate_translated_path_cache(ctx);
    return kbox_dispatch_from_lkl(ret);
}

/* forward_getcwd. */

static struct kbox_dispatch forward_getcwd(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t remote_buf = kbox_syscall_request_arg(req, 0);
    int64_t size_raw = to_c_long_arg(kbox_syscall_request_arg(req, 1));

    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);
    if (size_raw <= 0)
        return kbox_dispatch_errno(EINVAL);

    size_t size = (size_t) size_raw;
    if (size > KBOX_MAX_PATH)
        size = KBOX_MAX_PATH;

    char out[KBOX_MAX_PATH];
    long ret = kbox_lkl_getcwd(ctx->sysnrs, out, (long) size);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    size_t n = (size_t) ret;
    if (n == 0 || n > size)
        return kbox_dispatch_errno(EIO);

    int wrc = guest_mem_write(ctx, pid, remote_buf, out, n);
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value((int64_t) n);
}

/* forward_mkdirat. */

static struct kbox_dispatch forward_mkdirat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    int rc = translate_request_at_path(req, ctx, 0, 1, translated,
                                       sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);
    if (should_continue_for_dirfd(lkl_dirfd))
        return kbox_dispatch_continue();

    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long ret = kbox_lkl_mkdirat(ctx->sysnrs, lkl_dirfd, translated, mode);
    if (ret >= 0)
        invalidate_path_shadow_cache(ctx);
    return kbox_dispatch_from_lkl(ret);
}

/* forward_unlinkat. */

static struct kbox_dispatch forward_unlinkat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    int rc = translate_request_at_path(req, ctx, 0, 1, translated,
                                       sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);
    if (should_continue_for_dirfd(lkl_dirfd))
        return kbox_dispatch_continue();

    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long ret = kbox_lkl_unlinkat(ctx->sysnrs, lkl_dirfd, translated, flags);
    if (ret >= 0)
        invalidate_path_shadow_cache(ctx);
    return kbox_dispatch_from_lkl(ret);
}

/* forward_renameat / forward_renameat2. */

static struct kbox_dispatch do_renameat(const struct kbox_syscall_request *req,
                                        struct kbox_supervisor_ctx *ctx,
                                        long flags)
{
    char oldtrans[KBOX_MAX_PATH];
    char newtrans[KBOX_MAX_PATH];
    long olddirfd, newdirfd;
    int rc = translate_request_at_path(req, ctx, 0, 1, oldtrans,
                                       sizeof(oldtrans), &olddirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);
    rc = translate_request_at_path(req, ctx, 2, 3, newtrans, sizeof(newtrans),
                                   &newdirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);
    if (should_continue_for_dirfd(olddirfd))
        return kbox_dispatch_continue();
    if (should_continue_for_dirfd(newdirfd))
        return kbox_dispatch_continue();

    long ret = kbox_lkl_renameat2(ctx->sysnrs, olddirfd, oldtrans, newdirfd,
                                  newtrans, flags);
    if (ret >= 0)
        invalidate_path_shadow_cache(ctx);
    return kbox_dispatch_from_lkl(ret);
}

static struct kbox_dispatch forward_renameat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return do_renameat(req, ctx, 0);
}

static struct kbox_dispatch forward_renameat2(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return do_renameat(req, ctx,
                       to_c_long_arg(kbox_syscall_request_arg(req, 4)));
}

/* forward_fchmodat. */

static struct kbox_dispatch forward_fchmodat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    int rc = translate_request_at_path(req, ctx, 0, 1, translated,
                                       sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);
    if (should_continue_for_dirfd(lkl_dirfd))
        return kbox_dispatch_continue();

    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 3));
    long ret =
        kbox_lkl_fchmodat(ctx->sysnrs, lkl_dirfd, translated, mode, flags);
    return kbox_dispatch_from_lkl(ret);
}

/* forward_fchownat. */

static struct kbox_dispatch forward_fchownat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    int rc = translate_request_at_path(req, ctx, 0, 1, translated,
                                       sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);
    if (should_continue_for_dirfd(lkl_dirfd))
        return kbox_dispatch_continue();

    long owner = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long group = to_c_long_arg(kbox_syscall_request_arg(req, 3));
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 4));
    long ret = kbox_lkl_fchownat(ctx->sysnrs, lkl_dirfd, translated, owner,
                                 group, flags);
    return kbox_dispatch_from_lkl(ret);
}

/* forward_mount. */

static struct kbox_dispatch forward_mount(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    char srcbuf[KBOX_MAX_PATH];
    char tgtbuf[KBOX_MAX_PATH];
    char fsbuf[KBOX_MAX_PATH];
    char databuf[KBOX_MAX_PATH];
    int rc;

    const char *source = NULL;
    if (kbox_syscall_request_arg(req, 0) != 0) {
        rc = guest_mem_read_string(ctx, pid, kbox_syscall_request_arg(req, 0),
                                   srcbuf, sizeof(srcbuf));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        source = srcbuf;
    }

    rc = guest_mem_read_string(ctx, pid, kbox_syscall_request_arg(req, 1),
                               tgtbuf, sizeof(tgtbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    const char *fstype = NULL;
    if (kbox_syscall_request_arg(req, 2) != 0) {
        rc = guest_mem_read_string(ctx, pid, kbox_syscall_request_arg(req, 2),
                                   fsbuf, sizeof(fsbuf));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        fstype = fsbuf;
    }

    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 3));

    const void *data = NULL;
    if (kbox_syscall_request_arg(req, 4) != 0) {
        rc = guest_mem_read_string(ctx, pid, kbox_syscall_request_arg(req, 4),
                                   databuf, sizeof(databuf));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        data = databuf;
    }

    /* Translate paths through normalization and host-root confinement. */
    char translated_tgt[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, tgtbuf, ctx->host_root,
                                     translated_tgt, sizeof(translated_tgt));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    /* Translate the source for bind mounts (MS_BIND uses a path, not a
     * device).  Non-bind sources (device names, "none") pass through
     * unmodified.
     */
    char translated_src[KBOX_MAX_PATH];
    const char *effective_src = source;
    if (source && (flags & 0x1000 /* MS_BIND */)) {
        rc =
            kbox_translate_path_for_lkl(pid, srcbuf, ctx->host_root,
                                        translated_src, sizeof(translated_src));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        effective_src = translated_src;
    }

    long ret = kbox_lkl_mount(ctx->sysnrs, effective_src, translated_tgt,
                              fstype, flags, data);
    return kbox_dispatch_from_lkl(ret);
}

/* forward_umount2. */

static struct kbox_dispatch forward_umount2(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    char pathbuf[KBOX_MAX_PATH];
    int rc;

    rc = guest_mem_read_string(ctx, pid, kbox_syscall_request_arg(req, 0),
                               pathbuf, sizeof(pathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    char translated[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, pathbuf, ctx->host_root, translated,
                                     sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long ret = kbox_lkl_umount2(ctx->sysnrs, translated, flags);
    return kbox_dispatch_from_lkl(ret);
}

/* Legacy x86_64 syscall forwarders (stat, lstat, access, etc.). */

static struct kbox_dispatch forward_stat_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    int nofollow)
{
    char translated[KBOX_MAX_PATH];
    int rc = translate_request_path(req, ctx, 0, ctx->host_root, translated,
                                    sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    uint64_t remote_stat = kbox_syscall_request_arg(req, 1);
    if (remote_stat == 0)
        return kbox_dispatch_errno(EFAULT);

    if (translated[0] != '\0' &&
        try_cached_shadow_stat_dispatch(ctx, translated, remote_stat,
                                        kbox_syscall_request_pid(req))) {
        return kbox_dispatch_value(0);
    }

    long flags = nofollow ? AT_SYMLINK_NOFOLLOW : 0;

    struct kbox_lkl_stat kst;
    memset(&kst, 0, sizeof(kst));
    long ret = kbox_lkl_newfstatat(ctx->sysnrs, AT_FDCWD_LINUX, translated,
                                   &kst, flags);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    struct stat host_stat;
    kbox_lkl_stat_to_host(&kst, &host_stat);
    normalize_host_stat_if_needed(ctx, translated, &host_stat);

    int wrc = guest_mem_write_small_metadata(ctx, kbox_syscall_request_pid(req),
                                             remote_stat, &host_stat,
                                             sizeof(host_stat));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

static struct kbox_dispatch forward_access_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    int rc = translate_request_path(req, ctx, 0, ctx->host_root, translated,
                                    sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long ret =
        kbox_lkl_faccessat2(ctx->sysnrs, AT_FDCWD_LINUX, translated, mode, 0);
    return kbox_dispatch_from_lkl(ret);
}

static struct kbox_dispatch forward_mkdir_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    int rc = translate_request_path(req, ctx, 0, ctx->host_root, translated,
                                    sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long ret = kbox_lkl_mkdir(ctx->sysnrs, translated, (int) mode);
    return kbox_dispatch_from_lkl(ret);
}

static struct kbox_dispatch forward_unlink_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    int rc = translate_request_path(req, ctx, 0, ctx->host_root, translated,
                                    sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long ret = kbox_lkl_unlinkat(ctx->sysnrs, AT_FDCWD_LINUX, translated, 0);
    return kbox_dispatch_from_lkl(ret);
}

static struct kbox_dispatch forward_rmdir_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    int rc = translate_request_path(req, ctx, 0, ctx->host_root, translated,
                                    sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long ret = kbox_lkl_unlinkat(ctx->sysnrs, AT_FDCWD_LINUX, translated,
                                 AT_REMOVEDIR);
    return kbox_dispatch_from_lkl(ret);
}

static struct kbox_dispatch forward_rename_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char oldtrans[KBOX_MAX_PATH];
    char newtrans[KBOX_MAX_PATH];
    int rc = translate_request_path(req, ctx, 0, ctx->host_root, oldtrans,
                                    sizeof(oldtrans));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);
    rc = translate_request_path(req, ctx, 1, ctx->host_root, newtrans,
                                sizeof(newtrans));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long ret = kbox_lkl_renameat2(ctx->sysnrs, AT_FDCWD_LINUX, oldtrans,
                                  AT_FDCWD_LINUX, newtrans, 0);
    return kbox_dispatch_from_lkl(ret);
}

static struct kbox_dispatch forward_chmod_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    int rc = translate_request_path(req, ctx, 0, ctx->host_root, translated,
                                    sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long ret =
        kbox_lkl_fchmodat(ctx->sysnrs, AT_FDCWD_LINUX, translated, mode, 0);
    return kbox_dispatch_from_lkl(ret);
}

static struct kbox_dispatch forward_chown_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    int rc = translate_request_path(req, ctx, 0, ctx->host_root, translated,
                                    sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long owner = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long group = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long ret = kbox_lkl_fchownat(ctx->sysnrs, AT_FDCWD_LINUX, translated, owner,
                                 group, 0);
    return kbox_dispatch_from_lkl(ret);
}

/* Identity forwarders: getuid, geteuid, getresuid, etc. */

static struct kbox_dispatch forward_getresuid(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t ruid_ptr = kbox_syscall_request_arg(req, 0);
    uint64_t euid_ptr = kbox_syscall_request_arg(req, 1);
    uint64_t suid_ptr = kbox_syscall_request_arg(req, 2);

    if (ruid_ptr != 0) {
        long r = kbox_lkl_getuid(ctx->sysnrs);
        if (r < 0)
            return kbox_dispatch_errno((int) (-r));
        unsigned val = (unsigned) r;
        int wrc = guest_mem_write(ctx, pid, ruid_ptr, &val, sizeof(val));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }
    if (euid_ptr != 0) {
        long r = kbox_lkl_geteuid(ctx->sysnrs);
        if (r < 0)
            return kbox_dispatch_errno((int) (-r));
        unsigned val = (unsigned) r;
        int wrc = guest_mem_write(ctx, pid, euid_ptr, &val, sizeof(val));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }
    if (suid_ptr != 0) {
        /* saved-set-uid = effective uid (LKL has no separate saved). */
        long r = kbox_lkl_geteuid(ctx->sysnrs);
        if (r < 0)
            return kbox_dispatch_errno((int) (-r));
        unsigned val = (unsigned) r;
        int wrc = guest_mem_write(ctx, pid, suid_ptr, &val, sizeof(val));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }
    return kbox_dispatch_value(0);
}

static struct kbox_dispatch forward_getresuid_override(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    uid_t uid)
{
    pid_t pid = kbox_syscall_request_pid(req);
    unsigned val = (unsigned) uid;
    int i;

    for (i = 0; i < 3; i++) {
        uint64_t ptr = kbox_syscall_request_arg(req, i);
        if (ptr != 0) {
            int wrc = guest_mem_write(ctx, pid, ptr, &val, sizeof(val));
            if (wrc < 0)
                return kbox_dispatch_errno(EIO);
        }
    }
    return kbox_dispatch_value(0);
}

static struct kbox_dispatch forward_getresgid(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t rgid_ptr = kbox_syscall_request_arg(req, 0);
    uint64_t egid_ptr = kbox_syscall_request_arg(req, 1);
    uint64_t sgid_ptr = kbox_syscall_request_arg(req, 2);

    if (rgid_ptr != 0) {
        long r = kbox_lkl_getgid(ctx->sysnrs);
        if (r < 0)
            return kbox_dispatch_errno((int) (-r));
        unsigned val = (unsigned) r;
        int wrc = guest_mem_write(ctx, pid, rgid_ptr, &val, sizeof(val));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }
    if (egid_ptr != 0) {
        long r = kbox_lkl_getegid(ctx->sysnrs);
        if (r < 0)
            return kbox_dispatch_errno((int) (-r));
        unsigned val = (unsigned) r;
        int wrc = guest_mem_write(ctx, pid, egid_ptr, &val, sizeof(val));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }
    if (sgid_ptr != 0) {
        long r = kbox_lkl_getegid(ctx->sysnrs);
        if (r < 0)
            return kbox_dispatch_errno((int) (-r));
        unsigned val = (unsigned) r;
        int wrc = guest_mem_write(ctx, pid, sgid_ptr, &val, sizeof(val));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }
    return kbox_dispatch_value(0);
}

static struct kbox_dispatch forward_getresgid_override(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    gid_t gid)
{
    pid_t pid = kbox_syscall_request_pid(req);
    unsigned val = (unsigned) gid;
    int i;

    for (i = 0; i < 3; i++) {
        uint64_t ptr = kbox_syscall_request_arg(req, i);
        if (ptr != 0) {
            int wrc = guest_mem_write(ctx, pid, ptr, &val, sizeof(val));
            if (wrc < 0)
                return kbox_dispatch_errno(EIO);
        }
    }
    return kbox_dispatch_value(0);
}

static struct kbox_dispatch forward_getgroups(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long size = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    uint64_t list = kbox_syscall_request_arg(req, 1);

    if (size < 0)
        return kbox_dispatch_errno(EINVAL);

    /* Probe to get actual group count. */
    long count = kbox_lkl_getgroups(ctx->sysnrs, 0, NULL);
    if (count < 0)
        return kbox_dispatch_errno((int) (-count));

    if (size == 0)
        return kbox_dispatch_value((int64_t) count);

    /* Caller's buffer must be large enough. */
    if (size < count)
        return kbox_dispatch_errno(EINVAL);

    size_t byte_len = (size_t) count * sizeof(unsigned);
    if (byte_len > KBOX_IO_CHUNK_LEN)
        return kbox_dispatch_errno(ENOMEM);
    unsigned *buf = (unsigned *) dispatch_scratch;

    long ret = kbox_lkl_getgroups(ctx->sysnrs, count, buf);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    if (list != 0 && ret > 0) {
        size_t write_len = (size_t) ret * sizeof(unsigned);
        pid_t pid = kbox_syscall_request_pid(req);
        int wrc = guest_mem_write(ctx, pid, list, buf, write_len);
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }

    return kbox_dispatch_value((int64_t) ret);
}

static struct kbox_dispatch forward_getgroups_override(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    gid_t gid)
{
    long size = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    if (size < 0)
        return kbox_dispatch_errno(EINVAL);
    if (size == 0)
        return kbox_dispatch_value(1);

    uint64_t list = kbox_syscall_request_arg(req, 1);
    if (list == 0)
        return kbox_dispatch_errno(EFAULT);

    pid_t pid = kbox_syscall_request_pid(req);
    unsigned val = (unsigned) gid;
    int wrc = guest_mem_write(ctx, pid, list, &val, sizeof(val));
    if (wrc < 0)
        return kbox_dispatch_errno(EIO);

    return kbox_dispatch_value(1);
}

/* Identity set forwarders. */

static struct kbox_dispatch forward_setuid(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long uid = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    return kbox_dispatch_from_lkl(kbox_lkl_setuid(ctx->sysnrs, uid));
}

static struct kbox_dispatch forward_setreuid(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long ruid = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long euid = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    return kbox_dispatch_from_lkl(kbox_lkl_setreuid(ctx->sysnrs, ruid, euid));
}

static struct kbox_dispatch forward_setresuid(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long ruid = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long euid = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long suid = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    return kbox_dispatch_from_lkl(
        kbox_lkl_setresuid(ctx->sysnrs, ruid, euid, suid));
}

static struct kbox_dispatch forward_setgid(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long gid = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    return kbox_dispatch_from_lkl(kbox_lkl_setgid(ctx->sysnrs, gid));
}

static struct kbox_dispatch forward_setregid(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long rgid = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long egid = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    return kbox_dispatch_from_lkl(kbox_lkl_setregid(ctx->sysnrs, rgid, egid));
}

static struct kbox_dispatch forward_setresgid(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long rgid = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long egid = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long sgid = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    return kbox_dispatch_from_lkl(
        kbox_lkl_setresgid(ctx->sysnrs, rgid, egid, sgid));
}

static struct kbox_dispatch forward_setgroups(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long size = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    uint64_t list = kbox_syscall_request_arg(req, 1);

    if (size < 0 || size > 65536)
        return kbox_dispatch_errno(EINVAL);

    if (size == 0)
        return kbox_dispatch_from_lkl(kbox_lkl_setgroups(ctx->sysnrs, 0, NULL));

    size_t byte_len = (size_t) size * sizeof(unsigned);
    if (byte_len > KBOX_IO_CHUNK_LEN)
        return kbox_dispatch_errno(ENOMEM);
    unsigned *buf = (unsigned *) dispatch_scratch;

    pid_t pid = kbox_syscall_request_pid(req);
    int rrc = guest_mem_read(ctx, pid, list, buf, byte_len);
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    long ret = kbox_lkl_setgroups(ctx->sysnrs, size, buf);
    return kbox_dispatch_from_lkl(ret);
}

static struct kbox_dispatch forward_setfsgid(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long gid = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    return kbox_dispatch_from_lkl(kbox_lkl_setfsgid(ctx->sysnrs, gid));
}

/* forward_socket. */

/* Shadow socket design:
 *   1. Create an LKL socket (lives inside LKL's network stack)
 *   2. Create a host socketpair (sp[0]=supervisor, sp[1]=tracee)
 *   3. Inject sp[1] into the tracee via ADDFD
 *   4. Register sp[0]+lkl_fd with the SLIRP event loop
 *   5. The event loop pumps data between sp[0] and the LKL socket
 *
 * The tracee sees a real host FD, so poll/epoll/read/write all work natively
 * via the host kernel. Only control-plane ops (connect, getsockopt, etc.) need
 * explicit forwarding.
 *
 * INET sockets with SLIRP active get a shadow socket bridge so data flows
 * through the host kernel socketpair (bypassing BKL contention in blocking LKL
 * recv/send calls). Non-INET sockets and INET sockets without SLIRP use the
 * standard virtual FD path.
 *
 * Limitation: listen/accept on shadow sockets fail because the AF_UNIX
 * socketpair doesn't support inbound connections. Server sockets must be used
 * without --net or via a future deferred-bridge approach.
 */
static struct kbox_dispatch forward_socket(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long domain = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long type_raw = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long protocol = to_c_long_arg(kbox_syscall_request_arg(req, 2));

    int base_type = (int) type_raw & 0xFF;

    long ret = kbox_lkl_socket(ctx->sysnrs, domain, type_raw, protocol);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    long lkl_fd = ret;

    /* Virtual FD path when shadow bridge is not applicable:
     * - SLIRP not active (no --net)
     * - Non-INET domain (AF_UNIX, AF_NETLINK, etc.)
     * - Non-stream/datagram type (SOCK_RAW, etc.): socketpair(AF_UNIX)
     *   only supports SOCK_STREAM and SOCK_DGRAM
     */
    if (!kbox_net_is_active() ||
        (domain != 2 /* AF_INET */ && domain != 10 /* AF_INET6 */) ||
        (base_type != SOCK_STREAM && base_type != SOCK_DGRAM)) {
        long vfd = kbox_fd_table_insert(ctx->fd_table, lkl_fd, 0);
        if (vfd < 0) {
            lkl_close_and_invalidate(ctx, lkl_fd);
            return kbox_dispatch_errno(EMFILE);
        }
        return kbox_dispatch_value((int64_t) vfd);
    }

    /* Shadow socket bridge for INET with SLIRP. */
    int sp[2];
    if (socketpair(AF_UNIX, base_type | SOCK_CLOEXEC, 0, sp) < 0) {
        lkl_close_and_invalidate(ctx, lkl_fd);
        return kbox_dispatch_errno(errno);
    }
    fcntl(sp[0], F_SETFL, O_NONBLOCK);
    if (type_raw & SOCK_NONBLOCK)
        fcntl(sp[1], F_SETFL, O_NONBLOCK);

    long vfd = kbox_fd_table_insert(ctx->fd_table, lkl_fd, 0);
    if (vfd < 0) {
        close(sp[0]);
        close(sp[1]);
        lkl_close_and_invalidate(ctx, lkl_fd);
        return kbox_dispatch_errno(EMFILE);
    }

    if (kbox_net_register_socket((int) lkl_fd, sp[0], base_type) < 0) {
        close(sp[0]);
        close(sp[1]);
        /* Fall back to virtual FD. */
        return kbox_dispatch_value((int64_t) vfd);
    }

    uint32_t addfd_flags = 0;
    if (type_raw & SOCK_CLOEXEC)
        addfd_flags = O_CLOEXEC;
    int host_fd = request_addfd(ctx, req, sp[1], addfd_flags);
    if (host_fd < 0) {
        /* Deregister closes sp[0] and marks inactive. */
        kbox_net_deregister_socket((int) lkl_fd);
        close(sp[1]);
        kbox_fd_table_remove(ctx->fd_table, vfd);
        lkl_close_and_invalidate(ctx, lkl_fd);
        return kbox_dispatch_errno(-host_fd);
    }
    kbox_fd_table_set_host_fd(ctx->fd_table, vfd, host_fd);

    {
        struct kbox_fd_entry *e = NULL;
        if (vfd >= KBOX_FD_BASE)
            e = &ctx->fd_table->entries[vfd - KBOX_FD_BASE];
        else if (vfd >= 0 && vfd < KBOX_LOW_FD_MAX)
            e = &ctx->fd_table->low_fds[vfd];
        if (e) {
            e->shadow_sp = sp[1];
            if (type_raw & SOCK_CLOEXEC)
                e->cloexec = 1;
        }
    }

    return kbox_dispatch_value((int64_t) host_fd);
}

/* forward_bind / forward_connect. */

static long resolve_lkl_socket(struct kbox_supervisor_ctx *ctx, long fd);

static struct kbox_dispatch forward_bind(const struct kbox_syscall_request *req,
                                         struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = resolve_lkl_socket(ctx, fd);

    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t addr_ptr = kbox_syscall_request_arg(req, 1);
    int64_t len_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    if (len_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t len = (size_t) len_raw;

    if (addr_ptr == 0)
        return kbox_dispatch_errno(EFAULT);

    if (len > 4096)
        return kbox_dispatch_errno(EINVAL);

    uint8_t buf[4096];
    int rrc = guest_mem_read(ctx, pid, addr_ptr, buf, len);
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    long ret = kbox_lkl_bind(ctx->sysnrs, lkl_fd, buf, (long) len);
    return kbox_dispatch_from_lkl(ret);
}

/* forward_connect. */

/* Resolve LKL FD from a tracee FD.  The tracee may hold either a virtual FD
 * (>= KBOX_FD_BASE) or a host FD from a shadow socket (injected via ADDFD).
 * Try both paths.
 */
static long resolve_lkl_socket(struct kbox_supervisor_ctx *ctx, long fd)
{
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    if (lkl_fd >= 0)
        return lkl_fd;

    /* Shadow socket: tracee uses the host_fd directly. */
    long vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, fd);
    if (vfd >= 0)
        return kbox_fd_table_get_lkl(ctx->fd_table, vfd);

    return -1;
}

static struct kbox_dispatch forward_connect(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = resolve_lkl_socket(ctx, fd);

    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t addr_ptr = kbox_syscall_request_arg(req, 1);
    int64_t len_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    if (len_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t len = (size_t) len_raw;

    if (addr_ptr == 0)
        return kbox_dispatch_errno(EFAULT);

    if (len > 4096)
        return kbox_dispatch_errno(EINVAL);

    uint8_t buf[4096];
    int rrc = guest_mem_read(ctx, pid, addr_ptr, buf, len);
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    long ret = kbox_lkl_connect(ctx->sysnrs, lkl_fd, buf, (long) len);

    /* Propagate -EINPROGRESS directly for nonblocking sockets. The tracee's
     * poll(POLLOUT) on the AF_UNIX socketpair returns immediately (spurious
     * wakeup), but getsockopt(SO_ERROR) is forwarded to the LKL socket and
     * returns the real handshake status. The tracee retries poll+getsockopt
     * until SO_ERROR clears; standard nonblocking connect flow.
     */
    return kbox_dispatch_from_lkl(ret);
}

/* forward_getsockopt. */

static struct kbox_dispatch forward_getsockopt(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = resolve_lkl_socket(ctx, fd);
    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    pid_t pid = kbox_syscall_request_pid(req);
    long level = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long optname = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    uint64_t optval_ptr = kbox_syscall_request_arg(req, 3);
    uint64_t optlen_ptr = kbox_syscall_request_arg(req, 4);

    if (optval_ptr == 0 || optlen_ptr == 0)
        return kbox_dispatch_errno(EFAULT);

    /* Read the optlen from tracee. */
    unsigned int optlen;
    int rrc = guest_mem_read(ctx, pid, optlen_ptr, &optlen, sizeof(optlen));
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    if (optlen > 4096)
        return kbox_dispatch_errno(EINVAL);

    uint8_t optval[4096];
    unsigned int out_len = optlen;

    long ret = kbox_lkl_getsockopt(ctx->sysnrs, lkl_fd, level, optname, optval,
                                   &out_len);
    if (ret < 0)
        return kbox_dispatch_from_lkl(ret);

    /* Write min(out_len, optlen) to avoid leaking stack data. */
    unsigned int write_len = out_len < optlen ? out_len : optlen;
    int wrc = guest_mem_write(ctx, pid, optval_ptr, optval, write_len);
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);
    wrc = guest_mem_write(ctx, pid, optlen_ptr, &out_len, sizeof(out_len));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

/* forward_setsockopt. */

static struct kbox_dispatch forward_setsockopt(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = resolve_lkl_socket(ctx, fd);
    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    pid_t pid = kbox_syscall_request_pid(req);
    long level = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long optname = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    uint64_t optval_ptr = kbox_syscall_request_arg(req, 3);
    long optlen = to_c_long_arg(kbox_syscall_request_arg(req, 4));

    if (optlen < 0 || optlen > 4096)
        return kbox_dispatch_errno(EINVAL);

    uint8_t optval[4096] = {0};
    if (optval_ptr != 0 && optlen > 0) {
        int rrc = guest_mem_read(ctx, pid, optval_ptr, optval, (size_t) optlen);
        if (rrc < 0)
            return kbox_dispatch_errno(-rrc);
    }

    long ret = kbox_lkl_setsockopt(ctx->sysnrs, lkl_fd, level, optname,
                                   optval_ptr ? optval : NULL, optlen);
    return kbox_dispatch_from_lkl(ret);
}

/* forward_getsockname / forward_getpeername. */

typedef long (*sockaddr_query_fn)(const struct kbox_sysnrs *s,
                                  long fd,
                                  void *addr,
                                  void *addrlen);

static struct kbox_dispatch forward_sockaddr_query(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    sockaddr_query_fn query)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = resolve_lkl_socket(ctx, fd);
    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t addr_ptr = kbox_syscall_request_arg(req, 1);
    uint64_t len_ptr = kbox_syscall_request_arg(req, 2);

    if (addr_ptr == 0 || len_ptr == 0)
        return kbox_dispatch_errno(EFAULT);

    unsigned int addrlen;
    int rrc = guest_mem_read(ctx, pid, len_ptr, &addrlen, sizeof(addrlen));
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    if (addrlen > 4096)
        addrlen = 4096;

    uint8_t addr[4096];
    unsigned int out_len = addrlen;

    long ret = query(ctx->sysnrs, lkl_fd, addr, &out_len);
    if (ret < 0)
        return kbox_dispatch_from_lkl(ret);

    unsigned int write_len = out_len < addrlen ? out_len : addrlen;
    int wrc = guest_mem_write(ctx, pid, addr_ptr, addr, write_len);
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);
    wrc = guest_mem_write(ctx, pid, len_ptr, &out_len, sizeof(out_len));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

static struct kbox_dispatch forward_getsockname(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_sockaddr_query(req, ctx, kbox_lkl_getsockname);
}

static struct kbox_dispatch forward_getpeername(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_sockaddr_query(req, ctx, kbox_lkl_getpeername);
}

/* forward_shutdown. */

static struct kbox_dispatch forward_shutdown(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = resolve_lkl_socket(ctx, fd);
    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    long how = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long ret = kbox_lkl_shutdown(ctx->sysnrs, lkl_fd, how);
    return kbox_dispatch_from_lkl(ret);
}

/* forward_sendto / forward_recvfrom / forward_recvmsg. */

/* forward_sendto: for shadow sockets with a destination address, forward the
 * data + address directly to the LKL socket. This is needed for unconnected
 * UDP (DNS resolver uses sendto with sockaddr_in without prior connect).
 *
 * sendto(fd, buf, len, flags, dest_addr, addrlen)
 *   args[0]=fd, args[1]=buf, args[2]=len, args[3]=flags,
 *   args[4]=dest_addr, args[5]=addrlen
 */
static struct kbox_dispatch forward_sendto(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = resolve_lkl_socket(ctx, fd);
    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    uint64_t dest_ptr = kbox_syscall_request_arg(req, 4);
    if (dest_ptr == 0)
        return kbox_dispatch_continue(); /* no dest addr: stream data path */

    /* Has a destination address: forward via LKL sendto. */
    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t buf_ptr = kbox_syscall_request_arg(req, 1);
    int64_t len_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 3));
    int64_t addrlen_raw = to_c_long_arg(kbox_syscall_request_arg(req, 5));

    if (len_raw < 0 || addrlen_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t len = (size_t) len_raw;
    size_t addrlen = (size_t) addrlen_raw;

    if (len > 65536)
        len = 65536;
    if (addrlen > 128)
        return kbox_dispatch_errno(EINVAL);

    uint8_t buf[65536];
    uint8_t addr[128];

    int rrc = guest_mem_read(ctx, pid, buf_ptr, buf, len);
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);
    rrc = guest_mem_read(ctx, pid, dest_ptr, addr, addrlen);
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    long ret = kbox_lkl_sendto(ctx->sysnrs, lkl_fd, buf, (long) len, flags,
                               addr, (long) addrlen);
    return kbox_dispatch_from_lkl(ret);
}

/* forward_recvfrom: for shadow sockets, receive data + source address from
 * the LKL socket and write them back to the tracee.
 *
 * recvfrom(fd, buf, len, flags, src_addr, addrlen)
 *   args[0]=fd, args[1]=buf, args[2]=len, args[3]=flags,
 *   args[4]=src_addr, args[5]=addrlen
 */
static struct kbox_dispatch forward_recvfrom(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = resolve_lkl_socket(ctx, fd);
    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    uint64_t src_ptr = kbox_syscall_request_arg(req, 4);
    if (src_ptr == 0)
        return kbox_dispatch_continue(); /* no addr buffer: stream path */

    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t buf_ptr = kbox_syscall_request_arg(req, 1);
    int64_t len_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 3));
    uint64_t addrlen_ptr = kbox_syscall_request_arg(req, 5);

    if (len_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t len = (size_t) len_raw;
    if (len > 65536)
        len = 65536;

    unsigned int addrlen = 0;
    if (addrlen_ptr != 0) {
        int rrc =
            guest_mem_read(ctx, pid, addrlen_ptr, &addrlen, sizeof(addrlen));
        if (rrc < 0)
            return kbox_dispatch_errno(-rrc);
    }
    if (addrlen > 128)
        addrlen = 128;

    uint8_t buf[65536];
    uint8_t addr[128];
    unsigned int out_addrlen = addrlen;

    long ret = kbox_lkl_recvfrom(ctx->sysnrs, lkl_fd, buf, (long) len, flags,
                                 addr, &out_addrlen);
    if (ret < 0)
        return kbox_dispatch_from_lkl(ret);

    int wrc = guest_mem_write(ctx, pid, buf_ptr, buf, (size_t) ret);
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    if (src_ptr != 0 && out_addrlen > 0) {
        unsigned int write_len = out_addrlen < addrlen ? out_addrlen : addrlen;
        wrc = guest_mem_write(ctx, pid, src_ptr, addr, write_len);
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }
    if (addrlen_ptr != 0) {
        wrc = guest_mem_write(ctx, pid, addrlen_ptr, &out_addrlen,
                              sizeof(out_addrlen));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }

    return kbox_dispatch_value(ret);
}

/* forward_recvmsg: intercept for shadow sockets so that msg_name (source
 * address) is populated from the LKL socket, not the AF_UNIX socketpair.
 *
 * recvmsg(fd, msg, flags)
 *   args[0]=fd, args[1]=msg_ptr, args[2]=flags
 */
static struct kbox_dispatch forward_recvmsg(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = resolve_lkl_socket(ctx, fd);
    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t msg_ptr = kbox_syscall_request_arg(req, 1);
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 2));

    if (msg_ptr == 0)
        return kbox_dispatch_errno(EFAULT);

    struct {
        uint64_t msg_name;
        uint32_t msg_namelen;
        uint32_t __pad0;
        uint64_t msg_iov;
        uint64_t msg_iovlen;
        uint64_t msg_control;
        uint64_t msg_controllen;
        int msg_flags;
    } mh;
    int rrc = guest_mem_read(ctx, pid, msg_ptr, &mh, sizeof(mh));
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    /* No msg_name: for connected stream sockets, CONTINUE via socketpair. */
    if (mh.msg_name == 0 || mh.msg_namelen == 0)
        return kbox_dispatch_continue();

    /* Read all iovecs to determine total buffer capacity. */
    if (mh.msg_iovlen == 0)
        return kbox_dispatch_value(0);

    size_t niov = (size_t) mh.msg_iovlen;
    if (niov > 64)
        niov = 64;

    struct {
        uint64_t iov_base;
        uint64_t iov_len;
    } iovs[64];
    rrc = guest_mem_read(ctx, pid, mh.msg_iov, iovs, niov * sizeof(iovs[0]));
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    size_t total_cap = 0;
    for (size_t v = 0; v < niov; v++)
        total_cap += (size_t) iovs[v].iov_len;
    if (total_cap > 65536)
        total_cap = 65536;

    uint8_t buf[65536];
    uint8_t addr[128];
    unsigned int addrlen = mh.msg_namelen < sizeof(addr)
                               ? mh.msg_namelen
                               : (unsigned int) sizeof(addr);
    unsigned int out_addrlen = addrlen;

    long ret = kbox_lkl_recvfrom(ctx->sysnrs, lkl_fd, buf, (long) total_cap,
                                 flags, addr, &out_addrlen);
    if (ret < 0)
        return kbox_dispatch_from_lkl(ret);

    /* Scatter received data across tracee iov buffers. */
    size_t written = 0;
    for (size_t v = 0; v < niov && written < (size_t) ret; v++) {
        size_t chunk = (size_t) ret - written;
        if (chunk > (size_t) iovs[v].iov_len)
            chunk = (size_t) iovs[v].iov_len;
        if (chunk > 0 && iovs[v].iov_base != 0) {
            int wrc2 = guest_mem_write(ctx, pid, iovs[v].iov_base,
                                       buf + written, chunk);
            if (wrc2 < 0)
                return kbox_dispatch_errno(-wrc2);
            written += chunk;
        }
    }

    /* Write source address to tracee msg_name. */
    if (out_addrlen > 0) {
        unsigned int write_len =
            out_addrlen < mh.msg_namelen ? out_addrlen : mh.msg_namelen;
        int awrc = guest_mem_write(ctx, pid, mh.msg_name, addr, write_len);
        if (awrc < 0)
            return kbox_dispatch_errno(-awrc);
    }

    /* Update msg_namelen in the msghdr. */
    int nwrc =
        guest_mem_write(ctx, pid, msg_ptr + 8 /* offset of msg_namelen */,
                        &out_addrlen, sizeof(out_addrlen));
    if (nwrc < 0)
        return kbox_dispatch_errno(-nwrc);

    return kbox_dispatch_value(ret);
}

/* forward_clock_gettime. */

static struct kbox_dispatch forward_clock_gettime(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    int clockid = (int) to_c_long_arg(kbox_syscall_request_arg(req, 0));
    uint64_t remote_ts = kbox_syscall_request_arg(req, 1);

    if (remote_ts == 0)
        return kbox_dispatch_errno(EFAULT);

    struct timespec ts;
    if (clock_gettime(clockid, &ts) < 0)
        return kbox_dispatch_errno(errno);

    int wrc = guest_mem_write(ctx, pid, remote_ts, &ts, sizeof(ts));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

/* forward_clock_getres. */

static struct kbox_dispatch forward_clock_getres(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    int clockid = (int) to_c_long_arg(kbox_syscall_request_arg(req, 0));
    uint64_t remote_ts = kbox_syscall_request_arg(req, 1);

    struct timespec ts;
    if (clock_getres(clockid, remote_ts ? &ts : NULL) < 0)
        return kbox_dispatch_errno(errno);

    if (remote_ts != 0) {
        int wrc = guest_mem_write(ctx, pid, remote_ts, &ts, sizeof(ts));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }

    return kbox_dispatch_value(0);
}

/* forward_gettimeofday. */

static struct kbox_dispatch forward_gettimeofday(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t remote_tv = kbox_syscall_request_arg(req, 0);
    uint64_t remote_tz = kbox_syscall_request_arg(req, 1);

    /* Use clock_gettime(CLOCK_REALTIME) as the underlying source, which
     * works on both x86_64 and aarch64.
     */
    if (remote_tv != 0) {
        struct timespec ts;
        if (clock_gettime(CLOCK_REALTIME, &ts) < 0)
            return kbox_dispatch_errno(errno);

        struct {
            long tv_sec;
            long tv_usec;
        } tv;
        tv.tv_sec = ts.tv_sec;
        tv.tv_usec = ts.tv_nsec / 1000;

        int wrc = guest_mem_write(ctx, pid, remote_tv, &tv, sizeof(tv));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }

    if (remote_tz != 0) {
        /* Return zeroed timezone (UTC). */
        struct {
            int tz_minuteswest;
            int tz_dsttime;
        } tz = {0, 0};

        int wrc = guest_mem_write(ctx, pid, remote_tz, &tz, sizeof(tz));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }

    return kbox_dispatch_value(0);
}

/* forward_readlinkat. */

static struct kbox_dispatch forward_readlinkat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    long dirfd_raw = to_dirfd_arg(kbox_syscall_request_arg(req, 0));
    char pathbuf[KBOX_MAX_PATH];
    int rc = guest_mem_read_string(ctx, pid, kbox_syscall_request_arg(req, 1),
                                   pathbuf, sizeof(pathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    uint64_t remote_buf = kbox_syscall_request_arg(req, 2);
    int64_t bufsiz_raw = to_c_long_arg(kbox_syscall_request_arg(req, 3));
    if (bufsiz_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t bufsiz = (size_t) bufsiz_raw;

    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);

    char translated[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, pathbuf, ctx->host_root, translated,
                                     sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long lkl_dirfd = resolve_open_dirfd(translated, dirfd_raw, ctx->fd_table);
    if (lkl_dirfd < 0 && lkl_dirfd != AT_FDCWD_LINUX)
        return kbox_dispatch_continue();

    if (bufsiz > KBOX_MAX_PATH)
        bufsiz = KBOX_MAX_PATH;

    char linkbuf[KBOX_MAX_PATH];
    long ret = kbox_lkl_readlinkat(ctx->sysnrs, lkl_dirfd, translated, linkbuf,
                                   (long) bufsiz);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    size_t n = (size_t) ret;
    int wrc = guest_mem_write(ctx, pid, remote_buf, linkbuf, n);
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value((int64_t) n);
}

/* forward_pipe2. */

static struct kbox_dispatch forward_pipe2(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t remote_pipefd = kbox_syscall_request_arg(req, 0);
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 1));

    if (remote_pipefd == 0)
        return kbox_dispatch_errno(EFAULT);

    /* Create a real host pipe and inject both ends into the tracee via
     * SECCOMP_IOCTL_NOTIF_ADDFD.  This makes pipes fully native:
     *
     *   - dup2/close/read/write on pipe FDs -> CONTINUE (host kernel)
     *   - Proper fork semantics: both parent and child share the real
     *     pipe, no virtual FD table conflicts.
     *   - No LKL overhead for IPC data transfer.
     */
    int host_pipefd[2];
    if (pipe2(host_pipefd, (int) flags) < 0)
        return kbox_dispatch_errno(errno);

    uint32_t cloexec_flag = (flags & O_CLOEXEC) ? O_CLOEXEC : 0;

    int tracee_fd0 = request_addfd(ctx, req, host_pipefd[0], cloexec_flag);
    if (tracee_fd0 < 0) {
        close(host_pipefd[0]);
        close(host_pipefd[1]);
        return kbox_dispatch_errno(-tracee_fd0);
    }

    int tracee_fd1 = request_addfd(ctx, req, host_pipefd[1], cloexec_flag);
    if (tracee_fd1 < 0) {
        close(host_pipefd[0]);
        close(host_pipefd[1]);
        return kbox_dispatch_errno(-tracee_fd1);
    }

    /* Supervisor copies no longer needed; tracee owns its own copies. */
    close(host_pipefd[0]);
    close(host_pipefd[1]);

    int guest_fds[2] = {tracee_fd0, tracee_fd1};
    int wrc =
        guest_mem_write(ctx, pid, remote_pipefd, guest_fds, sizeof(guest_fds));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

/* forward_uname. */

static struct kbox_dispatch forward_uname(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t remote_buf = kbox_syscall_request_arg(req, 0);

    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);

    struct utsname uts;
    memset(&uts, 0, sizeof(uts));
    snprintf(uts.sysname, sizeof(uts.sysname), "Linux");
    snprintf(uts.nodename, sizeof(uts.nodename), "kbox");
    snprintf(uts.release, sizeof(uts.release), "6.8.0-kbox");
    snprintf(uts.version, sizeof(uts.version), "#1 SMP");
#if defined(__x86_64__)
    snprintf(uts.machine, sizeof(uts.machine), "x86_64");
#elif defined(__aarch64__)
    snprintf(uts.machine, sizeof(uts.machine), "aarch64");
#else
    snprintf(uts.machine, sizeof(uts.machine), "unknown");
#endif

    int wrc = guest_mem_write(ctx, pid, remote_buf, &uts, sizeof(uts));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

/* forward_getrandom. */

static struct kbox_dispatch forward_getrandom(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t remote_buf = kbox_syscall_request_arg(req, 0);
    int64_t buflen_raw = to_c_long_arg(kbox_syscall_request_arg(req, 1));

    if (buflen_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t buflen = (size_t) buflen_raw;

    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);
    if (buflen == 0)
        return kbox_dispatch_value(0);

    /* Read from /dev/urandom via LKL.  Fall back to host if LKL does not
     * have the device available.
     */
    size_t max_chunk = 256;
    if (buflen > max_chunk)
        buflen = max_chunk;

    uint8_t scratch[256];
    long fd = kbox_lkl_openat(ctx->sysnrs, AT_FDCWD_LINUX, "/dev/urandom",
                              O_RDONLY, 0);
    if (fd < 0) {
        /* Fallback: let host kernel handle it. */
        return kbox_dispatch_continue();
    }

    long ret = kbox_lkl_read(ctx->sysnrs, fd, scratch, (long) buflen);
    lkl_close_and_invalidate(ctx, fd);

    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    size_t n = (size_t) ret;
    int wrc = guest_mem_write(ctx, pid, remote_buf, scratch, n);
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value((int64_t) n);
}

/* forward_syslog (klogctl). */

/* syslog(type, buf, len): forward to LKL so dmesg shows the LKL kernel's
 * ring buffer, not the host's.
 *
 * Types that read into buf (2=READ, 3=READ_ALL, 4=READ_CLEAR): call LKL
 * with a scratch buffer, then copy to tracee.
 * Types that just return a value (0,1,5-10): forward type+len, return the
 * result directly.
 */
#define SYSLOG_ACTION_READ 2
#define SYSLOG_ACTION_READ_ALL 3
#define SYSLOG_ACTION_READ_CLEAR 4
#define SYSLOG_ACTION_SIZE_BUFFER 10

static struct kbox_dispatch forward_syslog(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    long type = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    uint64_t remote_buf = kbox_syscall_request_arg(req, 1);
    long len = to_c_long_arg(kbox_syscall_request_arg(req, 2));

    int needs_buf =
        (type == SYSLOG_ACTION_READ || type == SYSLOG_ACTION_READ_ALL ||
         type == SYSLOG_ACTION_READ_CLEAR);

    if (!needs_buf) {
        /* No buffer transfer: SIZE_BUFFER, CONSOLE_ON/OFF, etc. */
        long ret = lkl_syscall6(ctx->sysnrs->syslog, type, 0, len, 0, 0, 0);
        return kbox_dispatch_from_lkl(ret);
    }

    if (len <= 0)
        return kbox_dispatch_errno(EINVAL);
    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);

    /* Static buffer; safe because the supervisor is single-threaded.
     * Clamp to the actual LKL ring buffer size so READ_CLEAR never
     * discards data beyond what we can copy out.  The ring buffer size is
     * fixed at boot, so cache it after the first query.  Hard-cap at 1MB
     * (the static buffer size) as a safety ceiling.
     */
    static uint8_t scratch[1024 * 1024];
    static long cached_ring_sz;
    if (!cached_ring_sz) {
        long sz = lkl_syscall6(ctx->sysnrs->syslog, SYSLOG_ACTION_SIZE_BUFFER,
                               0, 0, 0, 0, 0);
        cached_ring_sz = (sz > 0) ? sz : -1;
    }
    if (cached_ring_sz > 0 && len > cached_ring_sz)
        len = cached_ring_sz;
    if (len > (long) sizeof(scratch))
        len = (long) sizeof(scratch);

    long ret =
        lkl_syscall6(ctx->sysnrs->syslog, type, (long) scratch, len, 0, 0, 0);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    size_t n = (size_t) ret;
    int wrc = guest_mem_write(ctx, pid, remote_buf, scratch, n);

    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value((int64_t) n);
}

/* forward_prctl. */

#ifndef PR_SET_NAME
#define PR_SET_NAME 15
#endif
#ifndef PR_GET_NAME
#define PR_GET_NAME 16
#endif
#ifndef PR_SET_DUMPABLE
#define PR_SET_DUMPABLE 4
#endif
#ifndef PR_GET_DUMPABLE
#define PR_GET_DUMPABLE 3
#endif

static struct kbox_dispatch forward_prctl(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long option = to_c_long_arg(kbox_syscall_request_arg(req, 0));

    /* Block PR_SET_DUMPABLE(0): clearing dumpability makes process_vm_readv
     * fail, which would bypass clone3 namespace-flag sanitization (the
     * supervisor can't read clone_args.flags from a non-dumpable process).
     * Return success without actually clearing; the tracee thinks it
     * worked, but the supervisor retains read access.
     */
    if (option == PR_SET_DUMPABLE &&
        to_c_long_arg(kbox_syscall_request_arg(req, 1)) == 0)
        return kbox_dispatch_value(0);
    /* Match: report dumpable even if guest tried to clear it. */
    if (option == PR_GET_DUMPABLE)
        return kbox_dispatch_value(1);

    /* Only forward PR_SET_NAME and PR_GET_NAME to LKL.  Everything else
     * passes through to the host kernel.
     *
     * PR_SET_NAME/PR_GET_NAME use a 16-byte name buffer.  The tracee
     * passes a pointer in arg2 which is in the tracee's address space,
     * not ours.  We must copy through kbox_vm_read/kbox_vm_write.
     */
    if (option != PR_SET_NAME && option != PR_GET_NAME)
        return kbox_dispatch_continue();

    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t remote_name = kbox_syscall_request_arg(req, 1);
    if (remote_name == 0)
        return kbox_dispatch_errno(EFAULT);

    /* PR_SET_NAME: read 16-byte name from tracee, pass local copy to LKL. */
    if (option == PR_SET_NAME) {
        char name[16];
        int rrc = guest_mem_read(ctx, pid, remote_name, name, sizeof(name));
        if (rrc < 0)
            return kbox_dispatch_errno(-rrc);
        name[15] = '\0'; /* ensure NUL termination */
        long ret =
            lkl_syscall6(ctx->sysnrs->prctl, option, (long) name, 0, 0, 0, 0);
        return kbox_dispatch_from_lkl(ret);
    }

    /* PR_GET_NAME: get name from LKL into local buffer, write to tracee. */
    char name[16] = {0};
    long ret =
        lkl_syscall6(ctx->sysnrs->prctl, option, (long) name, 0, 0, 0, 0);
    if (ret < 0)
        return kbox_dispatch_from_lkl(ret);
    int wrc = guest_mem_write(ctx, pid, remote_name, name, sizeof(name));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);
    return kbox_dispatch_value(0);
}

/* forward_umask. */

static struct kbox_dispatch forward_umask(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long mask = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long ret = kbox_lkl_umask(ctx->sysnrs, mask);
    return kbox_dispatch_from_lkl(ret);
}

/* forward_pwrite64. */

static struct kbox_dispatch forward_pwrite64(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);

    if (lkl_fd < 0)
        return kbox_dispatch_continue();
    if (entry && entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW)
        return kbox_dispatch_continue();

    invalidate_stat_cache_fd(ctx, lkl_fd);

    uint64_t remote_buf = kbox_syscall_request_arg(req, 1);
    int64_t count_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    if (count_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t count = (size_t) count_raw;
    long offset = to_c_long_arg(kbox_syscall_request_arg(req, 3));

    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);
    if (count == 0)
        return kbox_dispatch_value(0);

    pid_t pid = kbox_syscall_request_pid(req);
    size_t max_count = 1024 * 1024;
    if (count > max_count)
        count = max_count;

    size_t total = 0;
    uint8_t *scratch = dispatch_scratch;

    while (total < count) {
        size_t chunk_len = KBOX_IO_CHUNK_LEN;
        if (chunk_len > count - total)
            chunk_len = count - total;

        uint64_t remote = remote_buf + total;
        int rrc = guest_mem_read(ctx, pid, remote, scratch, chunk_len);
        if (rrc < 0) {
            if (total > 0)
                break;
            return kbox_dispatch_errno(-rrc);
        }

        long ret = kbox_lkl_pwrite64(ctx->sysnrs, lkl_fd, scratch,
                                     (long) chunk_len, offset + (long) total);
        if (ret < 0) {
            if (total == 0) {
                return kbox_dispatch_errno((int) (-ret));
            }
            break;
        }

        size_t n = (size_t) ret;
        total += n;
        if (n < chunk_len)
            break;
    }

    if (total > 0)
        invalidate_path_shadow_cache(ctx);
    return kbox_dispatch_value((int64_t) total);
}

/* forward_writev. */

/* iovec layout matches the kernel's: { void *iov_base; size_t iov_len; }
 * On 64-bit: 16 bytes per entry.
 */
#define IOV_ENTRY_SIZE 16
/* Match the kernel's UIO_MAXIOV.  The iov_buf is static (not stack-allocated)
 * because in trap/rewrite mode dispatch runs in signal handler context where
 * 16 KB on the stack risks overflow on threads with small stacks.  The
 * dispatcher is single-threaded (documented invariant), so a static buffer
 * is safe.
 */
#define IOV_MAX_COUNT 1024
static uint8_t iov_scratch[IOV_MAX_COUNT * IOV_ENTRY_SIZE];

static struct kbox_dispatch forward_writev(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    invalidate_stat_cache_fd(ctx, lkl_fd);

    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t remote_iov = kbox_syscall_request_arg(req, 1);
    int64_t iovcnt_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));

    if (iovcnt_raw <= 0 || iovcnt_raw > IOV_MAX_COUNT)
        return kbox_dispatch_errno(EINVAL);
    if (remote_iov == 0)
        return kbox_dispatch_errno(EFAULT);

    int iovcnt = (int) iovcnt_raw;
    size_t iov_bytes = (size_t) iovcnt * IOV_ENTRY_SIZE;

    int rrc = guest_mem_read(ctx, pid, remote_iov, iov_scratch, iov_bytes);
    if (rrc < 0) {
        return kbox_dispatch_errno(-rrc);
    }

    int mirror_host = kbox_fd_table_mirror_tty(ctx->fd_table, fd);
    size_t total = 0;
    uint8_t *scratch = dispatch_scratch;

    int err = 0;
    int i;
    for (i = 0; i < iovcnt; i++) {
        uint64_t base;
        uint64_t len;
        memcpy(&base, &iov_scratch[i * IOV_ENTRY_SIZE], 8);
        memcpy(&len, &iov_scratch[i * IOV_ENTRY_SIZE + 8], 8);

        if (base == 0 || len == 0)
            continue;

        size_t seg_total = 0;
        while (seg_total < len) {
            size_t chunk = KBOX_IO_CHUNK_LEN;
            if (chunk > len - seg_total)
                chunk = len - seg_total;

            rrc = guest_mem_read(ctx, pid, base + seg_total, scratch, chunk);
            if (rrc < 0) {
                err = -rrc;
                goto done;
            }

            long ret =
                kbox_lkl_write(ctx->sysnrs, lkl_fd, scratch, (long) chunk);
            if (ret < 0) {
                err = (int) (-ret);
                goto done;
            }

            size_t n = (size_t) ret;
            if (mirror_host && n > 0)
                (void) write(STDOUT_FILENO, scratch, n);

            seg_total += n;
            total += n;
            if (n < chunk)
                goto done;
        }
    }

done:
    if (total > 0)
        invalidate_path_shadow_cache(ctx);
    if (total == 0 && err)
        return kbox_dispatch_errno(err);
    return kbox_dispatch_value((int64_t) total);
}

/* forward_readv. */

static struct kbox_dispatch forward_readv(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t remote_iov = kbox_syscall_request_arg(req, 1);
    int64_t iovcnt_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));

    if (iovcnt_raw <= 0 || iovcnt_raw > IOV_MAX_COUNT)
        return kbox_dispatch_errno(EINVAL);
    if (remote_iov == 0)
        return kbox_dispatch_errno(EFAULT);

    int iovcnt = (int) iovcnt_raw;
    size_t iov_bytes = (size_t) iovcnt * IOV_ENTRY_SIZE;

    int rrc = guest_mem_read(ctx, pid, remote_iov, iov_scratch, iov_bytes);
    if (rrc < 0) {
        return kbox_dispatch_errno(-rrc);
    }

    size_t total = 0;
    uint8_t *scratch = dispatch_scratch;

    int i;
    for (i = 0; i < iovcnt; i++) {
        uint64_t base;
        uint64_t len;
        memcpy(&base, &iov_scratch[i * IOV_ENTRY_SIZE], 8);
        memcpy(&len, &iov_scratch[i * IOV_ENTRY_SIZE + 8], 8);

        if (base == 0 || len == 0)
            continue;

        size_t seg_total = 0;
        while (seg_total < len) {
            size_t chunk = KBOX_IO_CHUNK_LEN;
            if (chunk > len - seg_total)
                chunk = len - seg_total;

            long ret =
                kbox_lkl_read(ctx->sysnrs, lkl_fd, scratch, (long) chunk);
            if (ret < 0) {
                if (total == 0) {
                    return kbox_dispatch_errno((int) (-ret));
                }
                goto done_readv;
            }

            size_t n = (size_t) ret;
            if (n == 0)
                goto done_readv;

            int wrc = guest_mem_write(ctx, pid, base + seg_total, scratch, n);
            if (wrc < 0) {
                return kbox_dispatch_errno(-wrc);
            }

            seg_total += n;
            total += n;
            if (n < chunk)
                goto done_readv;
        }
    }

done_readv:
    return kbox_dispatch_value((int64_t) total);
}

/* forward_ftruncate. */

static struct kbox_dispatch forward_ftruncate(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);

    if (lkl_fd < 0)
        return kbox_dispatch_continue();
    if (entry && entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW)
        return kbox_dispatch_continue();

    long length = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long ret = kbox_lkl_ftruncate(ctx->sysnrs, lkl_fd, length);
    if (ret >= 0) {
        invalidate_path_shadow_cache(ctx);
        invalidate_stat_cache_fd(ctx, lkl_fd);
    }
    return kbox_dispatch_from_lkl(ret);
}

/* forward_fallocate. */

static struct kbox_dispatch forward_fallocate(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);

    if (lkl_fd < 0)
        return kbox_dispatch_continue();
    if (entry && entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW)
        return kbox_dispatch_continue();

    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long offset = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long len = to_c_long_arg(kbox_syscall_request_arg(req, 3));
    long ret = kbox_lkl_fallocate(ctx->sysnrs, lkl_fd, mode, offset, len);
    if (ret == -ENOSYS)
        return kbox_dispatch_errno(ENOSYS);
    if (ret >= 0) {
        invalidate_path_shadow_cache(ctx);
        invalidate_stat_cache_fd(ctx, lkl_fd);
    }
    return kbox_dispatch_from_lkl(ret);
}

/* forward_flock. */

static struct kbox_dispatch forward_flock(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd < 0)
        return kbox_dispatch_continue();

    long operation = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long ret = kbox_lkl_flock(ctx->sysnrs, lkl_fd, operation);
    return kbox_dispatch_from_lkl(ret);
}

/* forward_fsync. */

static struct kbox_dispatch forward_fsync(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);

    if (lkl_fd < 0)
        return kbox_dispatch_continue();
    if (entry && entry->shadow_writeback) {
        int rc = sync_shadow_writeback(ctx, entry);
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        return kbox_dispatch_value(0);
    }

    long ret = kbox_lkl_fsync(ctx->sysnrs, lkl_fd);
    return kbox_dispatch_from_lkl(ret);
}

/* forward_fdatasync. */

static struct kbox_dispatch forward_fdatasync(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);

    if (lkl_fd < 0)
        return kbox_dispatch_continue();
    if (entry && entry->shadow_writeback) {
        int rc = sync_shadow_writeback(ctx, entry);
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        return kbox_dispatch_value(0);
    }

    long ret = kbox_lkl_fdatasync(ctx->sysnrs, lkl_fd);
    return kbox_dispatch_from_lkl(ret);
}

/* forward_sync. */

static struct kbox_dispatch forward_sync(const struct kbox_syscall_request *req,
                                         struct kbox_supervisor_ctx *ctx)
{
    (void) req;
    long ret = kbox_lkl_sync(ctx->sysnrs);
    return kbox_dispatch_from_lkl(ret);
}

/* forward_symlinkat. */

static struct kbox_dispatch forward_symlinkat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    char targetbuf[KBOX_MAX_PATH];
    char linkpathbuf[KBOX_MAX_PATH];
    int rc;

    rc = guest_mem_read_string(ctx, pid, kbox_syscall_request_arg(req, 0),
                               targetbuf, sizeof(targetbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long newdirfd_raw = to_dirfd_arg(kbox_syscall_request_arg(req, 1));

    rc = guest_mem_read_string(ctx, pid, kbox_syscall_request_arg(req, 2),
                               linkpathbuf, sizeof(linkpathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    char linktrans[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, linkpathbuf, ctx->host_root,
                                     linktrans, sizeof(linktrans));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long newdirfd = resolve_open_dirfd(linktrans, newdirfd_raw, ctx->fd_table);
    if (newdirfd < 0 && newdirfd != AT_FDCWD_LINUX)
        return kbox_dispatch_continue();

    /* Target is stored as-is (not translated). */
    long ret = kbox_lkl_symlinkat(ctx->sysnrs, targetbuf, newdirfd, linktrans);
    if (ret >= 0)
        invalidate_path_shadow_cache(ctx);
    return kbox_dispatch_from_lkl(ret);
}

/* forward_linkat. */

static struct kbox_dispatch forward_linkat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    long olddirfd_raw = to_dirfd_arg(kbox_syscall_request_arg(req, 0));
    char oldpathbuf[KBOX_MAX_PATH];
    int rc;

    rc = guest_mem_read_string(ctx, pid, kbox_syscall_request_arg(req, 1),
                               oldpathbuf, sizeof(oldpathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long newdirfd_raw = to_dirfd_arg(kbox_syscall_request_arg(req, 2));
    char newpathbuf[KBOX_MAX_PATH];

    rc = guest_mem_read_string(ctx, pid, kbox_syscall_request_arg(req, 3),
                               newpathbuf, sizeof(newpathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 4));

    char oldtrans[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, oldpathbuf, ctx->host_root, oldtrans,
                                     sizeof(oldtrans));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    char newtrans[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, newpathbuf, ctx->host_root, newtrans,
                                     sizeof(newtrans));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long olddirfd = resolve_open_dirfd(oldtrans, olddirfd_raw, ctx->fd_table);
    if (olddirfd < 0 && olddirfd != AT_FDCWD_LINUX)
        return kbox_dispatch_continue();

    long newdirfd = resolve_open_dirfd(newtrans, newdirfd_raw, ctx->fd_table);
    if (newdirfd < 0 && newdirfd != AT_FDCWD_LINUX)
        return kbox_dispatch_continue();

    long ret = kbox_lkl_linkat(ctx->sysnrs, olddirfd, oldtrans, newdirfd,
                               newtrans, flags);
    if (ret >= 0)
        invalidate_path_shadow_cache(ctx);
    return kbox_dispatch_from_lkl(ret);
}

/* forward_utimensat. */

/* struct timespec is 16 bytes on 64-bit: tv_sec(8) + tv_nsec(8). */
#define TIMESPEC_SIZE 16

static struct kbox_dispatch forward_utimensat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    long dirfd_raw = to_dirfd_arg(kbox_syscall_request_arg(req, 0));

    /* pathname can be NULL for utimensat (operates on dirfd itself).  In
     * that case args[1] == 0.
     */
    const char *translated_path = NULL;
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    int rc;

    if (kbox_syscall_request_arg(req, 1) != 0) {
        char pathbuf[KBOX_MAX_PATH];
        rc = guest_mem_read_string(ctx, pid, kbox_syscall_request_arg(req, 1),
                                   pathbuf, sizeof(pathbuf));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);

        rc = kbox_translate_path_for_lkl(pid, pathbuf, ctx->host_root,
                                         translated, sizeof(translated));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);

        translated_path = translated;
        lkl_dirfd = resolve_open_dirfd(translated, dirfd_raw, ctx->fd_table);
        if (lkl_dirfd < 0 && lkl_dirfd != AT_FDCWD_LINUX)
            return kbox_dispatch_continue();
    } else {
        translated_path = NULL;
        /* dirfd must be a virtual FD when path is NULL. */
        lkl_dirfd = kbox_fd_table_get_lkl(ctx->fd_table, dirfd_raw);
        if (lkl_dirfd < 0)
            return kbox_dispatch_continue();
    }

    /* Read the times array (2 x struct timespec) if provided. */
    uint8_t times_buf[TIMESPEC_SIZE * 2];
    const void *times = NULL;
    if (kbox_syscall_request_arg(req, 2) != 0) {
        rc = guest_mem_read(ctx, pid, kbox_syscall_request_arg(req, 2),
                            times_buf, sizeof(times_buf));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        times = times_buf;
    }

    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 3));
    long ret = kbox_lkl_utimensat(ctx->sysnrs, lkl_dirfd, translated_path,
                                  times, flags);
    if (ret >= 0)
        invalidate_path_shadow_cache(ctx);
    return kbox_dispatch_from_lkl(ret);
}

/* forward_ioctl. */

/* Terminal ioctl constants. */
#ifndef TCGETS
#define TCGETS 0x5401
#endif
#ifndef TCSETS
#define TCSETS 0x5402
#endif
#ifndef TIOCGWINSZ
#define TIOCGWINSZ 0x5413
#endif
#ifndef TIOCSWINSZ
#define TIOCSWINSZ 0x5414
#endif
#ifndef TIOCGPGRP
#define TIOCGPGRP 0x540F
#endif
#ifndef TIOCSPGRP
#define TIOCSPGRP 0x5410
#endif
#ifndef TIOCSCTTY
#define TIOCSCTTY 0x540E
#endif

static struct kbox_dispatch forward_ioctl(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long cmd = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd < 0) {
        /* Host FD (stdin/stdout/stderr or pipe).  Most ioctls pass through
         * to the host kernel.  However, job-control ioctls (TIOCSPGRP/
         * TIOCGPGRP) fail with EPERM under seccomp-unotify because the
         * supervised child is not the session leader.  Return ENOTTY so
         * shells fall back to non-job-control mode instead of aborting.
         */
        if (cmd == TIOCSPGRP || cmd == TIOCGPGRP || cmd == TIOCSCTTY)
            return kbox_dispatch_errno(ENOTTY);
        return kbox_dispatch_continue();
    }

    (void) lkl_fd;

    /* For virtual FDs backed by LKL, terminal ioctls return ENOTTY since
     * LKL file-backed FDs are not terminals.  Non-terminal ioctls also
     * return ENOTTY, matching regular-file semantics.
     */
    return kbox_dispatch_errno(ENOTTY);
}

/* forward_mmap. */

/* mmap dispatch: if the FD is a virtual FD with no host shadow, create
 * the shadow on demand (lazy shadow) and inject it into the tracee at
 * the same FD number, then CONTINUE so the host kernel mmaps the real fd.
 *
 * Lazy shadow creation avoids the memfd_create + file-copy cost at every
 * open.  The shadow is only materialized when the guest actually mmaps.
 */
static struct kbox_dispatch forward_mmap(const struct kbox_syscall_request *req,
                                         struct kbox_supervisor_ctx *ctx)
{
    /* W^X enforcement for mmap in trap/rewrite mode. */
    if (request_uses_trap_signals(req)) {
        int prot = (int) kbox_syscall_request_arg(req, 2);
        if ((prot & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC)) {
            if (ctx->verbose)
                fprintf(stderr,
                        "kbox: mmap denied: W^X violation "
                        "(prot=0x%x, pid=%u)\n",
                        prot, kbox_syscall_request_pid(req));
            return kbox_dispatch_errno(EACCES);
        }
    }

    long fd = to_dirfd_arg(kbox_syscall_request_arg(req, 4));

    if (fd == -1)
        return kbox_dispatch_continue();

    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    if (lkl_fd >= 0) {
        long host = kbox_fd_table_get_host_fd(ctx->fd_table, fd);
        if (host == -1) {
            /* Only create lazy shadows for read-only/private mappings.
             * Writable MAP_SHARED mappings on LKL files cannot be
             * supported via memfd (writes would go to the copy, not LKL).
             */
            int mmap_flags = (int) kbox_syscall_request_arg(req, 3);
            int mmap_prot = (int) kbox_syscall_request_arg(req, 2);
            if ((mmap_flags & MAP_SHARED) && (mmap_prot & PROT_WRITE))
                return kbox_dispatch_errno(ENODEV);

            int memfd = kbox_shadow_create(ctx->sysnrs, lkl_fd);
            if (memfd < 0)
                return kbox_dispatch_errno(ENODEV);
            kbox_shadow_seal(memfd);
            int injected = request_addfd_at(ctx, req, memfd, (int) fd, 0);
            if (injected < 0) {
                close(memfd);
                return kbox_dispatch_errno(ENODEV);
            }
            /* Mark that a shadow was injected so repeated mmaps don't
             * re-create it.  Use -2 as a sentinel: host_fd >= 0 means
             * "supervisor-owned shadow fd" (closed on remove).  host_fd
             * == -2 means "tracee-owned shadow, don't close in supervisor."
             * fd_table_remove only closes host_fd when host_fd >= 0 AND
             * shadow_sp < 0, so -2 is safe.
             */
            kbox_fd_table_set_host_fd(ctx->fd_table, fd,
                                      KBOX_FD_HOST_SAME_FD_SHADOW);
            {
                struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);
                if (entry)
                    entry->shadow_sp = memfd;
            }
        }
    }

    return kbox_dispatch_continue();
}

/* Identity dispatch helpers                                          */
/*                                                                    */
/* In host+root_identity mode, get* returns 0 and set* returns 0.     */
/* In host+override mode, get* returns the override value.            */
/* In host+neither mode, CONTINUE to host kernel.                     */
/* In image mode, forward to LKL.                                     */

static struct kbox_dispatch dispatch_get_uid(
    long (*lkl_func)(const struct kbox_sysnrs *),
    struct kbox_supervisor_ctx *ctx)
{
    if (ctx->host_root) {
        if (ctx->root_identity)
            return kbox_dispatch_value(0);
        if (ctx->override_uid != (uid_t) -1)
            return kbox_dispatch_value((int64_t) ctx->override_uid);
        return kbox_dispatch_continue();
    }
    return kbox_dispatch_from_lkl(lkl_func(ctx->sysnrs));
}

static struct kbox_dispatch dispatch_get_gid(
    long (*lkl_func)(const struct kbox_sysnrs *),
    struct kbox_supervisor_ctx *ctx)
{
    if (ctx->host_root) {
        if (ctx->root_identity)
            return kbox_dispatch_value(0);
        if (ctx->override_gid != (gid_t) -1)
            return kbox_dispatch_value((int64_t) ctx->override_gid);
        return kbox_dispatch_continue();
    }
    return kbox_dispatch_from_lkl(lkl_func(ctx->sysnrs));
}

static struct kbox_dispatch dispatch_set_id(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    struct kbox_dispatch (*lkl_forward)(const struct kbox_syscall_request *req,
                                        struct kbox_supervisor_ctx *ctx))
{
    if (ctx->host_root) {
        if (ctx->root_identity)
            return kbox_dispatch_value(0);
        return kbox_dispatch_continue();
    }
    return lkl_forward(req, ctx);
}

/* forward_execve. */

/* AT_EMPTY_PATH flag for execveat: indicates fexecve() usage.  Defined
 * here to avoid pulling in the full linux/fcntl.h.
 */
#define KBOX_AT_EMPTY_PATH 0x1000

/* Load biases for the userspace ELF loader.  Must match image.c
 * prepare_userspace_launch.  The loader places main and interpreter
 * ELFs at these fixed virtual addresses, and the stack just below
 * stack_top.
 */
#define KBOX_EXEC_MAIN_LOAD_BIAS 0x600000000000ULL
#define KBOX_EXEC_INTERP_LOAD_BIAS 0x610000000000ULL
#define KBOX_EXEC_STACK_TOP 0x700000010000ULL

/* Alternate stack region for userspace re-exec.  During re-exec the
 * SIGSYS handler is running on the old guest stack, so we cannot
 * unmap it until after transferring to the new binary.  Place the
 * new stack at a different address; the old stack region is reclaimed
 * by the subsequent munmap in teardown_old_guest_mappings during the
 * NEXT re-exec.
 */
#define KBOX_EXEC_REEXEC_STACK_TOP 0x6F0000010000ULL

/* Maximum entries in argv or envp for userspace exec. */
#define KBOX_EXEC_MAX_ARGS 4096

/* Track which stack region is in use by the current guest.  The
 * initial launch uses KBOX_EXEC_STACK_TOP; re-exec alternates
 * between the two addresses.  The signal handler runs on the
 * current guest's stack, so we must not unmap it during re-exec.
 */
static uint64_t reexec_current_stack_top;

/* Safely count a null-terminated pointer array in guest address space.
 * Uses process_vm_readv to avoid SIGSEGV on bad guest pointers.
 * Returns the count (not including the final NULL), or -EFAULT on bad memory.
 */
static long count_user_ptrs_safe(uint64_t arr_addr, size_t max_count)
{
    size_t n = 0;
    uint64_t ptr;

    if (arr_addr == 0)
        return -EFAULT;

    while (n < max_count) {
        uint64_t offset, probe_addr;
        int rc;
        if (__builtin_mul_overflow((uint64_t) n, sizeof(uint64_t), &offset) ||
            __builtin_add_overflow(arr_addr, offset, &probe_addr))
            return -EFAULT;
        rc = kbox_current_read(probe_addr, &ptr, sizeof(ptr));
        if (rc < 0)
            return -EFAULT;
        if (ptr == 0)
            return (long) n;
        n++;
    }

    return -E2BIG;
}

/* Safely measure the length of a guest string.
 * Returns the length (not including NUL), or -EFAULT on bad memory.
 */
static long strlen_user_safe(uint64_t str_addr)
{
    char buf[256];
    size_t total = 0;

    if (str_addr == 0)
        return -EFAULT;

    for (;;) {
        int rc = kbox_current_read(str_addr + total, buf, sizeof(buf));
        if (rc < 0)
            return -EFAULT;
        for (size_t i = 0; i < sizeof(buf); i++) {
            if (buf[i] == '\0')
                return (long) (total + i);
        }
        total += sizeof(buf);
        if (total > (size_t) (256 * 1024))
            return -ENAMETOOLONG;
    }
}

/* Safely read a single guest pointer (8 bytes). */
static int read_user_ptr(uint64_t addr, uint64_t *out)
{
    return kbox_current_read(addr, out, sizeof(*out));
}

/* Safely copy a guest string into a destination buffer.
 * Returns the string length (not including NUL), or -EFAULT.
 */
static long copy_user_string(uint64_t str_addr, char *dst, size_t dst_size)
{
    return kbox_current_read_string(str_addr, dst, dst_size);
}

/* Tear down old guest code/data mappings and the stale stack at the
 * new stack address.  The current guest stack (which the SIGSYS
 * handler is running on) is at the OTHER address and left alone.
 * It leaks one stack-sized region until the next re-exec cycle.
 */
static void teardown_old_guest_mappings(uint64_t new_stack_top)
{
    /* Main binary region: up to 256 MB from the load bias. */
    munmap((void *) (uintptr_t) KBOX_EXEC_MAIN_LOAD_BIAS, 256UL * 1024 * 1024);
    /* Interpreter region: up to 256 MB from the load bias. */
    munmap((void *) (uintptr_t) KBOX_EXEC_INTERP_LOAD_BIAS,
           256UL * 1024 * 1024);
    /* Unmap any stale stack at the new stack address.  On the first
     * re-exec (new = REEXEC), this is a no-op (nothing mapped there).
     * On the second re-exec (new = STACK_TOP), this unmaps the
     * initial launch stack.  Subsequent cycles alternate and reclaim.
     */
    munmap((void *) (uintptr_t) (new_stack_top - 16UL * 1024 * 1024),
           16UL * 1024 * 1024 + 0x10000UL);
}

/* Perform userspace exec for trap mode.  Called from inside the SIGSYS
 * handler when the guest calls execve/execveat.  This replaces the
 * current process image without a real exec syscall, preserving the
 * SIGSYS handler and seccomp filter chain.
 *
 * The function is noreturn on success: it transfers control to the new
 * binary's entry point.  On failure, it returns a dispatch with errno.
 */
static struct kbox_dispatch trap_userspace_exec(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    int exec_memfd,
    const char *pathname,
    int is_execveat)
{
    unsigned char *elf_buf = NULL;
    size_t elf_buf_len = 0;
    char interp_path[256];
    int interp_memfd = -1;
    int ilen = 0;
    struct kbox_loader_launch_spec spec;
    struct kbox_loader_launch launch = {0};
    struct kbox_syscall_trap_ip_range ranges[KBOX_LOADER_MAX_MAPPINGS];
    struct kbox_loader_exec_range exec_ranges[KBOX_LOADER_MAX_MAPPINGS];
    size_t exec_count = 0;
    size_t range_count = 0;
    unsigned char random_bytes[KBOX_LOADER_RANDOM_SIZE];

    /* execve(path, argv, envp):      argv=args[1], envp=args[2]
     * execveat(dirfd, path, argv, envp, flags): argv=args[2], envp=args[3]
     *
     * In trap mode these are guest pointers in our address space, but still
     * guest-controlled.  All accesses must use safe reads (process_vm_readv)
     * to return EFAULT on bad pointers instead of crashing the SIGSYS handler.
     */
    uint64_t argv_addr = kbox_syscall_request_arg(req, is_execveat ? 2 : 1);
    uint64_t envp_addr = kbox_syscall_request_arg(req, is_execveat ? 3 : 2);
    long argc_long = count_user_ptrs_safe(argv_addr, KBOX_EXEC_MAX_ARGS);
    long envc_long = count_user_ptrs_safe(envp_addr, KBOX_EXEC_MAX_ARGS);
    size_t argc, envc;

    if (argc_long < 0) {
        close(exec_memfd);
        return kbox_dispatch_errno(argc_long == -E2BIG ? EINVAL : EFAULT);
    }
    if (envc_long < 0) {
        close(exec_memfd);
        return kbox_dispatch_errno(envc_long == -E2BIG ? EINVAL : EFAULT);
    }
    argc = (size_t) argc_long;
    envc = (size_t) envc_long;
    if (argc == 0) {
        close(exec_memfd);
        return kbox_dispatch_errno(EINVAL);
    }

    /* Deep-copy argv and envp into a single mmap'd arena.  Using mmap
     * instead of malloc/strdup because we are inside the SIGSYS handler
     * and glibc's allocator is not async-signal-safe.
     *
     * Two passes: first measure total size (via safe string length reads),
     * then copy.  All guest pointer reads use process_vm_readv.
     */
    size_t arena_size = (argc + envc) * sizeof(char *);
    for (size_t i = 0; i < argc; i++) {
        uint64_t str_addr;
        long slen;
        if (read_user_ptr(argv_addr + i * sizeof(uint64_t), &str_addr) < 0) {
            close(exec_memfd);
            return kbox_dispatch_errno(EFAULT);
        }
        slen = strlen_user_safe(str_addr);
        if (slen < 0) {
            close(exec_memfd);
            return kbox_dispatch_errno(EFAULT);
        }
        arena_size += (size_t) slen + 1;
    }
    for (size_t i = 0; i < envc; i++) {
        uint64_t str_addr;
        long slen;
        if (read_user_ptr(envp_addr + i * sizeof(uint64_t), &str_addr) < 0) {
            close(exec_memfd);
            return kbox_dispatch_errno(EFAULT);
        }
        slen = strlen_user_safe(str_addr);
        if (slen < 0) {
            close(exec_memfd);
            return kbox_dispatch_errno(EFAULT);
        }
        arena_size += (size_t) slen + 1;
    }
    arena_size = (arena_size + 4095) & ~(size_t) 4095;

    char *arena = mmap(NULL, arena_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (arena == MAP_FAILED) {
        close(exec_memfd);
        return kbox_dispatch_errno(ENOMEM);
    }
    size_t arena_used = 0;
    char **argv_copy = (char **) (arena + arena_used);
    arena_used += argc * sizeof(char *);
    char **envp_copy = (char **) (arena + arena_used);
    arena_used += envc * sizeof(char *);
    for (size_t i = 0; i < argc; i++) {
        uint64_t str_addr;
        long slen;
        if (read_user_ptr(argv_addr + i * sizeof(uint64_t), &str_addr) < 0)
            goto fail_arena;
        slen = copy_user_string(str_addr, arena + arena_used,
                                arena_size - arena_used);
        if (slen < 0)
            goto fail_arena;
        argv_copy[i] = arena + arena_used;
        arena_used += (size_t) slen + 1;
    }
    for (size_t i = 0; i < envc; i++) {
        uint64_t str_addr;
        long slen;
        if (read_user_ptr(envp_addr + i * sizeof(uint64_t), &str_addr) < 0)
            goto fail_arena;
        slen = copy_user_string(str_addr, arena + arena_used,
                                arena_size - arena_used);
        if (slen < 0)
            goto fail_arena;
        envp_copy[i] = arena + arena_used;
        arena_used += (size_t) slen + 1;
    }

    /* Check for PT_INTERP (dynamic binary needing an interpreter). */
    if (kbox_read_elf_header_window_fd(exec_memfd, &elf_buf, &elf_buf_len) ==
        0) {
        uint64_t pt_offset, pt_filesz;

        ilen = kbox_find_elf_interp_loc(elf_buf, elf_buf_len, interp_path,
                                        sizeof(interp_path), &pt_offset,
                                        &pt_filesz);
        munmap(elf_buf, elf_buf_len);
        elf_buf = NULL;

        if (ilen < 0) {
            ilen = -ENOEXEC;
            goto fail_early;
        }

        if (ilen > 0) {
            long interp_lkl = kbox_lkl_openat(ctx->sysnrs, AT_FDCWD_LINUX,
                                              interp_path, O_RDONLY, 0);
            if (interp_lkl < 0) {
                if (ctx->verbose)
                    fprintf(stderr,
                            "kbox: trap exec %s: cannot open "
                            "interpreter %s: %s\n",
                            pathname, interp_path, kbox_err_text(interp_lkl));
                ilen = (int) interp_lkl;
                goto fail_early;
            }

            interp_memfd = kbox_shadow_create(ctx->sysnrs, interp_lkl);
            lkl_close_and_invalidate(ctx, interp_lkl);

            if (interp_memfd < 0) {
                ilen = interp_memfd;
                goto fail_early;
            }
        }
    }
    /* else: kbox_read_elf_header_window_fd failed, elf_buf is still NULL.
     * Nothing to unmap. Treat as static binary (no interpreter).
     */

    /* Generate random bytes for AT_RANDOM auxv entry.  Use the raw
     * syscall to avoid depending on sys/random.h availability.
     */
    memset(random_bytes, 0x42, sizeof(random_bytes));
#ifdef __NR_getrandom
    {
        long gr =
            syscall(__NR_getrandom, random_bytes, sizeof(random_bytes), 0);
        (void) gr;
    }
#endif

    /* Pick a stack address that does not collide with the old guest
     * stack (which we are currently running on from inside the SIGSYS
     * handler).  Alternate between two stack tops so the old one
     * survives until the next re-exec reclaims it.
     */
    uint64_t new_stack_top =
        (reexec_current_stack_top == KBOX_EXEC_REEXEC_STACK_TOP)
            ? KBOX_EXEC_STACK_TOP
            : KBOX_EXEC_REEXEC_STACK_TOP;

    /* Build the loader launch spec.  Use the same load biases as the
     * initial launch so the address space layout is consistent.
     */
    memset(&spec, 0, sizeof(spec));
    spec.exec_fd = exec_memfd;
    spec.interp_fd = interp_memfd;
    spec.argv = (const char *const *) argv_copy;
    spec.argc = argc;
    spec.envp = (const char *const *) envp_copy;
    spec.envc = envc;
    spec.execfn = pathname;
    spec.random_bytes = random_bytes;
    spec.page_size = (uint64_t) sysconf(_SC_PAGESIZE);
    spec.stack_top = new_stack_top;
    spec.main_load_bias = KBOX_EXEC_MAIN_LOAD_BIAS;
    spec.interp_load_bias = KBOX_EXEC_INTERP_LOAD_BIAS;
    spec.uid = ctx->root_identity ? 0 : (uint32_t) getuid();
    spec.euid = ctx->root_identity ? 0 : (uint32_t) getuid();
    spec.gid = ctx->root_identity ? 0 : (uint32_t) getgid();
    spec.egid = ctx->root_identity ? 0 : (uint32_t) getgid();
    spec.secure = 0;

    /* Tear down old guest code/data mappings BEFORE materializing new
     * ones (MAP_FIXED_NOREPLACE requires the addresses to be free).
     * But do NOT teardown before reading the memfds; the reads use
     * pread which doesn't depend on the old mappings.
     */
    teardown_old_guest_mappings(new_stack_top);

    {
        int launch_rc = kbox_loader_prepare_launch(&spec, &launch);
        if (launch_rc < 0) {
            const char msg[] = "kbox: trap exec: loader prepare failed\n";
            (void) write(STDERR_FILENO, msg, sizeof(msg) - 1);
            _exit(127);
        }
    }

    /* The memfds have been read into launch buffers; close them. */
    close(exec_memfd);
    if (interp_memfd >= 0)
        close(interp_memfd);

    /* Collect executable ranges from the new layout for the BPF
     * filter.  The new filter is appended to the filter chain; the
     * old filter is harmless (matches unmapped addresses).
     */
    if (kbox_loader_collect_exec_ranges(
            &launch, exec_ranges, KBOX_LOADER_MAX_MAPPINGS, &exec_count) < 0) {
        if (ctx->verbose)
            fprintf(stderr, "kbox: trap exec %s: cannot collect exec ranges\n",
                    pathname);
        kbox_loader_launch_reset(&launch);
        _exit(127);
    }
    for (size_t i = 0; i < exec_count; i++) {
        ranges[i].start = (uintptr_t) exec_ranges[i].start;
        ranges[i].end = (uintptr_t) exec_ranges[i].end;
    }
    range_count = exec_count;

    /* Install a new BPF RET_TRAP filter covering the new binary's
     * executable ranges.  seccomp filters form a chain; calling
     * seccomp(SET_MODE_FILTER) adds to it rather than replacing.
     */
    if (kbox_install_seccomp_trap_ranges(ctx->host_nrs, ranges, range_count) <
        0) {
        if (ctx->verbose)
            fprintf(stderr,
                    "kbox: trap exec %s: cannot install new BPF filter\n",
                    pathname);
        kbox_loader_launch_reset(&launch);
        _exit(127);
    }

    /* Clean up CLOEXEC entries from the FD table, matching what a
     * real exec would do.
     */
    kbox_fd_table_close_cloexec(ctx->fd_table, ctx->sysnrs);

    /* If the original launch used rewrite mode, re-apply binary rewriting
     * to the new binary.  This patches syscall instructions in the newly
     * loaded executable segments and sets up trampoline regions, promoting
     * the new binary from Tier 1 (SIGSYS ~3us) to Tier 2 (~41ns) for
     * rewritten sites.
     *
     * If rewrite installation fails (e.g., trampoline allocation), the
     * binary still works correctly via the SIGSYS handler (Tier 1).
     */
    if (req->source == KBOX_SYSCALL_SOURCE_REWRITE) {
        /* Static: the runtime is stored globally via
         * store_active_rewrite_runtime and must survive past the noreturn
         * transfer_to_guest. Single-threaded trap mode guarantees no concurrent
         * re-exec.
         */
        static struct kbox_rewrite_runtime rewrite_rt;
        kbox_rewrite_runtime_reset(&rewrite_rt);
        if (kbox_rewrite_runtime_install(&rewrite_rt, ctx, &launch) == 0) {
            if (ctx->verbose)
                fprintf(stderr,
                        "kbox: trap exec %s: rewrite installed "
                        "(%zu trampoline regions)\n",
                        pathname, rewrite_rt.trampoline_region_count);
        } else {
            if (ctx->verbose)
                fprintf(stderr,
                        "kbox: trap exec %s: rewrite failed, "
                        "falling back to SIGSYS\n",
                        pathname);
        }
    }

#if defined(__x86_64__)
    /* Reset the guest FS base to the host (kbox) FS base.  We are
     * inside the SIGSYS handler where FS already points to kbox's
     * TLS.  The new binary starts with no TLS set up; it will call
     * arch_prctl(ARCH_SET_FS) during libc init to establish its own.
     * Until then, SIGSYS handler entry should see FS == host FS and
     * the save/restore becomes a no-op, which is correct.
     */
    {
        uint64_t host_fs = 0;

        kbox_syscall_trap_host_arch_prctl_get_fs(&host_fs);
        kbox_syscall_trap_set_guest_fs(host_fs);
    }
#endif

    if (ctx->verbose)
        fprintf(stderr,
                "kbox: trap exec %s: transferring to new image "
                "pc=0x%llx sp=0x%llx\n",
                pathname, (unsigned long long) launch.transfer.pc,
                (unsigned long long) launch.transfer.sp);

    /* Record which stack the new guest is using.  The next re-exec
     * will pick the other address and reclaim this one.
     */
    reexec_current_stack_top = new_stack_top;

    /* Free staging buffers before transferring.  The image regions
     * (mmap'd guest code/data/stack) must survive.
     */
    munmap(arena, arena_size);
    if (launch.main_elf && launch.main_elf_len > 0)
        munmap(launch.main_elf, launch.main_elf_len);
    launch.main_elf = NULL;
    if (launch.interp_elf && launch.interp_elf_len > 0)
        munmap(launch.interp_elf, launch.interp_elf_len);
    launch.interp_elf = NULL;
    kbox_loader_stack_image_reset(&launch.layout.stack);

    /* Unblock SIGSYS before transferring.  We are inside the SIGSYS
     * handler, which runs with SIGSYS blocked (SA_SIGINFO default).
     * Since we jump to the new entry point instead of returning from
     * the handler, the kernel never restores the pre-handler signal
     * mask.  The new binary needs SIGSYS unblocked so the BPF RET_TRAP
     * filter can deliver it.
     */
    {
        uint64_t mask[2] = {0, 0};
        unsigned int signo = SIGSYS - 1;
        mask[signo / 64] = 1ULL << (signo % 64);
        kbox_syscall_trap_host_rt_sigprocmask_unblock(mask,
                                                      8 /* kernel sigset_t */);
    }

    /* Transfer control to the new binary.  This is noreturn. */
    kbox_loader_transfer_to_guest(&launch.transfer);

fail_arena:
    munmap(arena, arena_size);
    close(exec_memfd);
    return kbox_dispatch_errno(EFAULT);

fail_early:
    munmap(arena, arena_size);
    close(exec_memfd);
    if (interp_memfd >= 0)
        close(interp_memfd);
    return kbox_dispatch_errno((int) (-ilen));
}

/* Handle execve/execveat from inside the image.
 *
 * For fexecve (execveat with AT_EMPTY_PATH on a host memfd): CONTINUE,
 * the host kernel handles it directly.  This is the initial exec path
 * from image.c.
 *
 * For in-image exec (e.g. shell runs /bin/ls):
 *   1. Read the pathname from tracee memory
 *   2. Open the binary from LKL, create a memfd
 *   3. Check for PT_INTERP; if dynamic, extract interpreter into a second
 *      memfd and patch PT_INTERP to /proc/self/fd/N
 *   4. Inject memfds into the tracee via ADDFD
 *   5. Overwrite the pathname in tracee memory with /proc/self/fd/N
 *   6. CONTINUE: kernel re-reads the rewritten path and execs
 *
 * The seccomp-unotify guarantees the tracee is blocked during steps 1-5,
 * and the kernel has not yet copied the pathname (getname happens after
 * the seccomp check), so the overwrite is race-free.
 */
static struct kbox_dispatch forward_execve(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    int is_execveat)
{
    pid_t pid = kbox_syscall_request_pid(req);

    /* Detect fexecve: execveat(fd, "", argv, envp, AT_EMPTY_PATH).  This
     * is the initial exec from image.c on the host memfd.  Let the kernel
     * handle it directly.
     */
    if (is_execveat) {
        long flags = to_c_long_arg(kbox_syscall_request_arg(req, 4));
        if (flags & KBOX_AT_EMPTY_PATH)
            return kbox_dispatch_continue();
    }

    /* Read pathname from tracee memory. */
    uint64_t path_addr = is_execveat ? kbox_syscall_request_arg(req, 1)
                                     : kbox_syscall_request_arg(req, 0);
    char pathbuf[KBOX_MAX_PATH];
    int rc =
        guest_mem_read_string(ctx, pid, path_addr, pathbuf, sizeof(pathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    /* Translate path for LKL. */
    char translated[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, pathbuf, ctx->host_root, translated,
                                     sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    /* Virtual paths (/proc, /sys, /dev): let the host handle them. */
    if (kbox_is_lkl_virtual_path(translated))
        return kbox_dispatch_continue();

    /* Open the binary from LKL. */
    long lkl_fd =
        kbox_lkl_openat(ctx->sysnrs, AT_FDCWD_LINUX, translated, O_RDONLY, 0);
    if (lkl_fd < 0)
        return kbox_dispatch_errno((int) (-lkl_fd));

    /* Create a memfd with the binary contents. */
    int exec_memfd = kbox_shadow_create(ctx->sysnrs, lkl_fd);
    lkl_close_and_invalidate(ctx, lkl_fd);

    if (exec_memfd < 0)
        return kbox_dispatch_errno(-exec_memfd);

    /* Trap mode: the SIGSYS handler and BPF filter do not survive a
     * real exec, so perform a userspace exec instead.  This replaces
     * the process image in-place (unmap old, map new, jump to entry)
     * without invoking the kernel's execve.  On success the function
     * does not return.
     */
    if (request_uses_trap_signals(req))
        return trap_userspace_exec(req, ctx, exec_memfd, pathbuf, is_execveat);

    /* Check for PT_INTERP (dynamic binary). */
    {
        unsigned char *elf_buf = NULL;
        size_t elf_buf_len = 0;

        if (kbox_read_elf_header_window_fd(exec_memfd, &elf_buf,
                                           &elf_buf_len) == 0) {
            char interp_path[256];
            uint64_t pt_offset, pt_filesz;
            int ilen = kbox_find_elf_interp_loc(
                elf_buf, elf_buf_len, interp_path, sizeof(interp_path),
                &pt_offset, &pt_filesz);

            munmap(elf_buf, elf_buf_len);

            if (ilen < 0) {
                close(exec_memfd);
                return kbox_dispatch_errno(ENOEXEC);
            }

            if (ilen > 0) {
                /* Dynamic binary.  Extract the interpreter from LKL and
                 * inject it into the tracee.
                 */
                long interp_lkl = kbox_lkl_openat(ctx->sysnrs, AT_FDCWD_LINUX,
                                                  interp_path, O_RDONLY, 0);
                if (interp_lkl < 0) {
                    if (ctx->verbose)
                        fprintf(stderr,
                                "kbox: exec %s: cannot open "
                                "interpreter %s: %s\n",
                                pathbuf, interp_path,
                                kbox_err_text(interp_lkl));
                    close(exec_memfd);
                    return kbox_dispatch_errno((int) (-interp_lkl));
                }

                int interp_memfd = kbox_shadow_create(ctx->sysnrs, interp_lkl);
                lkl_close_and_invalidate(ctx, interp_lkl);

                if (interp_memfd < 0) {
                    close(exec_memfd);
                    return kbox_dispatch_errno(-interp_memfd);
                }

                /* Inject the interpreter memfd first so we know its FD
                 * number in the tracee for the PT_INTERP patch.  O_CLOEXEC
                 * is safe: the kernel resolves /proc/self/fd/N via
                 * open_exec() before begin_new_exec() closes CLOEXEC
                 * descriptors.
                 */
                int tracee_interp_fd =
                    request_addfd(ctx, req, interp_memfd, O_CLOEXEC);
                close(interp_memfd);

                if (tracee_interp_fd < 0) {
                    close(exec_memfd);
                    return kbox_dispatch_errno(-tracee_interp_fd);
                }

                /* Patch PT_INTERP in the exec memfd to point at the
                 * injected interpreter: /proc/self/fd/<N>.
                 */
                char new_interp[64];
                int new_len = snprintf(new_interp, sizeof(new_interp),
                                       "/proc/self/fd/%d", tracee_interp_fd);

                if ((uint64_t) (new_len + 1) > pt_filesz) {
                    close(exec_memfd);
                    return kbox_dispatch_errno(ENOMEM);
                }

                char patch[256];
                size_t patch_len = (size_t) pt_filesz;
                if (patch_len > sizeof(patch))
                    patch_len = sizeof(patch);
                memset(patch, 0, patch_len);
                memcpy(patch, new_interp, (size_t) new_len);

                if (pwrite(exec_memfd, patch, patch_len, (off_t) pt_offset) !=
                    (ssize_t) patch_len) {
                    close(exec_memfd);
                    return kbox_dispatch_errno(EIO);
                }

                if (ctx->verbose)
                    fprintf(stderr,
                            "kbox: exec %s: interpreter %s "
                            "-> /proc/self/fd/%d\n",
                            pathbuf, interp_path, tracee_interp_fd);
            }
        } else {
            munmap(elf_buf, elf_buf_len);
        }
    }

    /* Inject the exec memfd into the tracee.  O_CLOEXEC keeps the tracee's
     * FD table clean after exec succeeds.
     */
    int tracee_exec_fd = request_addfd(ctx, req, exec_memfd, O_CLOEXEC);
    close(exec_memfd);

    if (tracee_exec_fd < 0)
        return kbox_dispatch_errno(-tracee_exec_fd);

    /* Overwrite the pathname in the tracee's memory with /proc/self/fd/<N>.
     * The kernel has not yet copied the pathname (getname happens after
     * the seccomp check), so when we CONTINUE, it reads our rewritten
     * path.
     *
     * argv[0] aliasing: some shells pass the same pointer for pathname
     * and argv[0].  If we overwrite the pathname, we corrupt argv[0].
     * Detect this and fix it by writing the original path right after
     * the new path in the same buffer, then updating the argv[0] pointer
     * in the argv array.
     *
     * Try process_vm_writev first (fast path).  If that fails (e.g.
     * pathname is in .rodata), fall back to /proc/pid/mem which can
     * write through page protections.
     */
    char new_path[64];
    int new_path_len = snprintf(new_path, sizeof(new_path), "/proc/self/fd/%d",
                                tracee_exec_fd);

    /* Check if argv[0] is aliased with the pathname. argv pointer is args[1]
     * for execve, args[2] for execveat.
     */
    uint64_t argv_addr = is_execveat ? kbox_syscall_request_arg(req, 2)
                                     : kbox_syscall_request_arg(req, 1);
    uint64_t argv0_ptr = 0;
    int argv0_aliased = 0;

    if (argv_addr != 0) {
        rc = guest_mem_read(ctx, pid, argv_addr, &argv0_ptr, sizeof(argv0_ptr));
        if (rc == 0 && argv0_ptr == path_addr)
            argv0_aliased = 1;
    }

    /* Build the write buffer: new_path + NUL + original_path + NUL. Original
     * path goes right after the new path so we can point argv[0] at it.
     */
    size_t orig_len = strlen(pathbuf);
    size_t total_write = (size_t) (new_path_len + 1);

    if (argv0_aliased)
        total_write += orig_len + 1;

    char write_buf[KBOX_MAX_PATH + 64];
    if (total_write > sizeof(write_buf))
        return kbox_dispatch_errno(ENAMETOOLONG);

    memcpy(write_buf, new_path, (size_t) (new_path_len + 1));
    if (argv0_aliased)
        memcpy(write_buf + new_path_len + 1, pathbuf, orig_len + 1);

    rc = guest_mem_write(ctx, pid, path_addr, write_buf, total_write);
    if (rc < 0) {
        rc = guest_mem_write_force(ctx, pid, path_addr, write_buf, total_write);
        if (rc < 0) {
            if (ctx->verbose)
                fprintf(stderr,
                        "kbox: exec %s: cannot rewrite "
                        "pathname: %s\n",
                        pathbuf, strerror(-rc));
            return kbox_dispatch_errno(ENOEXEC);
        }
    }

    /* If argv[0] was aliased, update the argv[0] pointer to point at original
     * path copy (right after the new path).
     */
    if (argv0_aliased) {
        uint64_t new_argv0 = path_addr + (uint64_t) (new_path_len + 1);
        rc =
            guest_mem_write(ctx, pid, argv_addr, &new_argv0, sizeof(new_argv0));
        if (rc < 0)
            guest_mem_write_force(ctx, pid, argv_addr, &new_argv0,
                                  sizeof(new_argv0));
    }

    if (ctx->verbose)
        fprintf(stderr, "kbox: exec %s -> /proc/self/fd/%d\n", pathbuf,
                tracee_exec_fd);

    /* Clean up CLOEXEC entries from the FD table, matching what a
     * successful exec will do in the kernel.
     *
     * This is still conservative: if exec later fails, the tracee resumes
     * after we have already purged those mappings. That rollback problem is
     * preferable to keeping stale mappings alive across a successful exec,
     * which misroutes future FD operations in the new image.
     */
    kbox_fd_table_close_cloexec(ctx->fd_table, ctx->sysnrs);

    /* Invalidate the cached /proc/pid/mem FD. After exec, the kernel
     * may revoke access to the old FD even though the PID is the same
     * (credential check against the new binary). Forcing a reopen on
     * the next write ensures we have valid access.
     */
    if (ctx->proc_mem_fd >= 0) {
        close(ctx->proc_mem_fd);
        ctx->proc_mem_fd = -1;
    }

    return kbox_dispatch_continue();
}

/* clone3 namespace-flag sanitization. */

/* CLONE_NEW* flags that clone3 can smuggle in via clone_args.flags. The BPF
 * deny-list blocks unshare/setns, but clone3 bypasses it unless we check here.
 */
#ifndef CLONE_NEWNS
#define CLONE_NEWNS 0x00020000ULL
#endif
#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080ULL
#endif
#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000ULL
#endif
#ifndef CLONE_NEWUTS
#define CLONE_NEWUTS 0x04000000ULL
#endif
#ifndef CLONE_NEWIPC
#define CLONE_NEWIPC 0x08000000ULL
#endif
#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000ULL
#endif
#ifndef CLONE_NEWPID
#define CLONE_NEWPID 0x20000000ULL
#endif
#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000ULL
#endif
#ifndef CLONE_THREAD
#define CLONE_THREAD 0x00010000ULL
#endif

#define CLONE_NEW_MASK                                              \
    (CLONE_NEWNS | CLONE_NEWTIME | CLONE_NEWCGROUP | CLONE_NEWUTS | \
     CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET)

/* W^X enforcement for mprotect in trap/rewrite mode.
 *
 * Reject simultaneous PROT_WRITE|PROT_EXEC to prevent JIT spray attacks.
 * On none->X transitions, scan the page for syscall/sysenter/SVC instructions
 * and add them to the origin map for rewrite-mode caller validation.
 *
 * In seccomp mode, this is a no-op: CONTINUE lets the host kernel handle it.
 */
static struct kbox_dispatch forward_mprotect(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    uint64_t addr = kbox_syscall_request_arg(req, 0);
    uint64_t len = kbox_syscall_request_arg(req, 1);
    int prot = (int) kbox_syscall_request_arg(req, 2);

    /* In seccomp mode (supervisor), just pass through. */
    if (!request_uses_trap_signals(req))
        return kbox_dispatch_continue();

    /* W^X enforcement: reject PROT_WRITE | PROT_EXEC. */
    if ((prot & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC)) {
        if (ctx->verbose)
            fprintf(stderr,
                    "kbox: mprotect denied: W^X violation at 0x%llx len=%llu "
                    "(pid=%u)\n",
                    (unsigned long long) addr, (unsigned long long) len,
                    kbox_syscall_request_pid(req));
        return kbox_dispatch_errno(EACCES);
    }

    /* Allow the mprotect to proceed via host kernel. If the page transitions
     * to PROT_EXEC, JIT code on it will take the Tier 1 (RET_TRAP) slow path
     * because it won't be in the BPF allow ranges. This is safe: un-rewritten
     * syscall instructions in JIT pages are caught by the SIGSYS handler.
     *
     * Full scan-on-X (rewriting JIT pages at mprotect time) is a future
     * optimization: it would promote JIT pages from Tier 1 (~3us) to Tier 2
     * (~41ns) but requires synchronous instruction scanning while the page
     * is still writable, which adds latency to the mprotect call.
     */
    return kbox_dispatch_continue();
}

static struct kbox_dispatch forward_clone3(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    uint64_t flags;
    int rc;

    /* clone3(struct clone_args *args, size_t size). flags is the first uint64_t
     * field in clone_args. We only need to read the first 8 bytes.
     */
    rc =
        guest_mem_read(ctx, kbox_syscall_request_pid(req),
                       kbox_syscall_request_arg(req, 0), &flags, sizeof(flags));
    if (rc < 0) {
        /* Can't read tracee memory; fail closed with EPERM.
         *
         * CONTINUE is unsafe here: a tracee can clear dumpability via
         * prctl(PR_SET_DUMPABLE, 0), causing process_vm_readv to fail with
         * EPERM. If we CONTINUE, clone3 reaches host kernel with unchecked
         * namespace flags: a sandbox escape. Returning EPERM is the only safe
         * option.
         */
        if (ctx->verbose)
            fprintf(stderr,
                    "kbox: clone3 denied: cannot read clone_args "
                    "(pid=%u, rc=%d)\n",
                    kbox_syscall_request_pid(req), rc);
        return kbox_dispatch_errno(EPERM);
    }

    if (flags & CLONE_NEW_MASK) {
        if (ctx->verbose)
            fprintf(stderr,
                    "kbox: clone3 denied: namespace flags 0x%llx "
                    "(pid=%u)\n",
                    (unsigned long long) (flags & CLONE_NEW_MASK),
                    kbox_syscall_request_pid(req));
        return kbox_dispatch_errno(EPERM);
    }

    /* In trap/rewrite mode, block thread creation (CLONE_THREAD).
     * Multi-threaded guests require --syscall-mode=seccomp.
     */
    if ((flags & CLONE_THREAD) && request_uses_trap_signals(req)) {
        if (ctx->verbose)
            fprintf(stderr,
                    "kbox: clone3 denied: CLONE_THREAD in trap/rewrite mode "
                    "(pid=%u, use --syscall-mode=seccomp)\n",
                    kbox_syscall_request_pid(req));
        return kbox_dispatch_errno(EPERM);
    }

    return kbox_dispatch_continue();
}

/* Main dispatch function. */

struct kbox_dispatch kbox_dispatch_request(
    struct kbox_supervisor_ctx *ctx,
    const struct kbox_syscall_request *req)
{
    const struct kbox_host_nrs *h = ctx->host_nrs;
    int nr;

    if (!ctx || !req)
        return kbox_dispatch_errno(EINVAL);

    kbox_dispatch_prepare_request_ctx(ctx, req);
    nr = req->nr;

    if (ctx->verbose) {
        const char *name = syscall_name_from_nr(h, nr);
        fprintf(stderr, "%s syscall: pid=%u nr=%d (%s)\n",
                req->source == KBOX_SYSCALL_SOURCE_SECCOMP ? "seccomp notify"
                                                           : "in-process",
                kbox_syscall_request_pid(req), nr, name ? name : "unknown");
    }

    /* Legacy x86_64 syscalls. */

    if (nr == h->stat)
        return forward_stat_legacy(req, ctx, 0);
    if (nr == h->lstat)
        return forward_stat_legacy(req, ctx, 1);
    if (nr == h->access)
        return forward_access_legacy(req, ctx);
    if (nr == h->mkdir)
        return forward_mkdir_legacy(req, ctx);
    if (nr == h->rmdir)
        return forward_rmdir_legacy(req, ctx);
    if (nr == h->unlink)
        return forward_unlink_legacy(req, ctx);
    if (nr == h->rename)
        return forward_rename_legacy(req, ctx);
    if (nr == h->chmod)
        return forward_chmod_legacy(req, ctx);
    if (nr == h->chown)
        return forward_chown_legacy(req, ctx);
    if (nr == h->open)
        return forward_open_legacy(req, ctx);

    /* File open/create. */

    if (nr == h->openat)
        return forward_openat(req, ctx);
    if (nr == h->openat2)
        return forward_openat2(req, ctx);

    /* Metadata. */

    if (nr == h->fstat)
        return forward_fstat(req, ctx);
    if (nr == h->newfstatat)
        return forward_newfstatat(req, ctx);
    if (nr == h->statx)
        return forward_statx(req, ctx);
    if (nr == h->faccessat && h->faccessat > 0)
        return forward_faccessat(req, ctx);
    if (nr == h->faccessat2)
        return forward_faccessat2(req, ctx);

    /* Directories. */

    if (nr == h->getdents64)
        return forward_getdents64(req, ctx);
    if (nr == h->getdents)
        return forward_getdents(req, ctx);
    if (nr == h->mkdirat)
        return forward_mkdirat(req, ctx);
    if (nr == h->unlinkat)
        return forward_unlinkat(req, ctx);
    if (nr == h->renameat && h->renameat > 0)
        return forward_renameat(req, ctx);
    if (nr == h->renameat2)
        return forward_renameat2(req, ctx);
    if (nr == h->fchmodat)
        return forward_fchmodat(req, ctx);
    if (nr == h->fchownat)
        return forward_fchownat(req, ctx);

    /* Navigation. */

    if (nr == h->chdir)
        return forward_chdir(req, ctx);
    if (nr == h->fchdir)
        return forward_fchdir(req, ctx);
    if (nr == h->getcwd)
        return forward_getcwd(req, ctx);

    /* Identity: UID. */

    if (nr == h->getuid)
        return dispatch_get_uid(kbox_lkl_getuid, ctx);
    if (nr == h->geteuid)
        return dispatch_get_uid(kbox_lkl_geteuid, ctx);
    if (nr == h->getresuid) {
        if (ctx->host_root) {
            if (ctx->root_identity)
                return forward_getresuid_override(req, ctx, 0);
            if (ctx->override_uid != (uid_t) -1)
                return forward_getresuid_override(req, ctx, ctx->override_uid);
            return kbox_dispatch_continue();
        }
        return forward_getresuid(req, ctx);
    }

    /* Identity: GID. */

    if (nr == h->getgid)
        return dispatch_get_gid(kbox_lkl_getgid, ctx);
    if (nr == h->getegid)
        return dispatch_get_gid(kbox_lkl_getegid, ctx);
    if (nr == h->getresgid) {
        if (ctx->host_root) {
            if (ctx->root_identity)
                return forward_getresgid_override(req, ctx, 0);
            if (ctx->override_gid != (gid_t) -1)
                return forward_getresgid_override(req, ctx, ctx->override_gid);
            return kbox_dispatch_continue();
        }
        return forward_getresgid(req, ctx);
    }

    /* Identity: groups. */

    if (nr == h->getgroups) {
        if (ctx->host_root) {
            if (ctx->root_identity)
                return forward_getgroups_override(req, ctx, 0);
            if (ctx->override_gid != (gid_t) -1)
                return forward_getgroups_override(req, ctx, ctx->override_gid);
            return kbox_dispatch_continue();
        }
        return forward_getgroups(req, ctx);
    }

    /* Identity: set*. */

    if (nr == h->setuid)
        return dispatch_set_id(req, ctx, forward_setuid);
    if (nr == h->setreuid)
        return dispatch_set_id(req, ctx, forward_setreuid);
    if (nr == h->setresuid)
        return dispatch_set_id(req, ctx, forward_setresuid);
    if (nr == h->setgid)
        return dispatch_set_id(req, ctx, forward_setgid);
    if (nr == h->setregid)
        return dispatch_set_id(req, ctx, forward_setregid);
    if (nr == h->setresgid)
        return dispatch_set_id(req, ctx, forward_setresgid);
    if (nr == h->setgroups)
        return dispatch_set_id(req, ctx, forward_setgroups);
    if (nr == h->setfsgid)
        return dispatch_set_id(req, ctx, forward_setfsgid);

    /* Mount. */

    if (nr == h->mount)
        return forward_mount(req, ctx);
    if (nr == h->umount2)
        return forward_umount2(req, ctx);

    /* FD operations. */

    if (nr == h->close)
        return forward_close(req, ctx);
    if (nr == h->fcntl)
        return forward_fcntl(req, ctx);
    if (nr == h->dup)
        return forward_dup(req, ctx);
    if (nr == h->dup2)
        return forward_dup2(req, ctx);
    if (nr == h->dup3)
        return forward_dup3(req, ctx);

    /* I/O. */

    if (nr == h->read)
        return forward_read_like(req, ctx, 0);
    if (nr == h->pread64)
        return forward_read_like(req, ctx, 1);
    if (nr == h->write)
        return forward_write(req, ctx);
    if (nr == h->lseek)
        return forward_lseek(req, ctx);

    /* Networking. */

    if (nr == h->socket)
        return forward_socket(req, ctx);
    if (nr == h->bind)
        return forward_bind(req, ctx);
    if (nr == h->connect)
        return forward_connect(req, ctx);
    if (nr == h->sendto)
        return forward_sendto(req, ctx);
    if (nr == h->recvfrom)
        return forward_recvfrom(req, ctx);
    /* sendmsg: BPF allow-listed (SCM_RIGHTS), never reaches here.
     * Shadow socket callers should use sendto for addressed datagrams.
     */
    if (nr == h->recvmsg)
        return forward_recvmsg(req, ctx);
    if (nr == h->getsockopt)
        return forward_getsockopt(req, ctx);
    if (nr == h->setsockopt)
        return forward_setsockopt(req, ctx);
    if (nr == h->getsockname)
        return forward_getsockname(req, ctx);
    if (nr == h->getpeername)
        return forward_getpeername(req, ctx);
    if (nr == h->shutdown)
        return forward_shutdown(req, ctx);

    /* I/O extended. */

    if (nr == h->pwrite64)
        return forward_pwrite64(req, ctx);
    if (nr == h->writev)
        return forward_writev(req, ctx);
    if (nr == h->readv)
        return forward_readv(req, ctx);
    if (nr == h->ftruncate)
        return forward_ftruncate(req, ctx);
    if (nr == h->fallocate)
        return forward_fallocate(req, ctx);
    if (nr == h->flock)
        return forward_flock(req, ctx);
    if (nr == h->fsync)
        return forward_fsync(req, ctx);
    if (nr == h->fdatasync)
        return forward_fdatasync(req, ctx);
    if (nr == h->sync)
        return forward_sync(req, ctx);
    if (nr == h->ioctl)
        return forward_ioctl(req, ctx);

    /* File operations. */

    if (nr == h->readlinkat)
        return forward_readlinkat(req, ctx);
    if (nr == h->pipe2)
        return forward_pipe2(req, ctx);
    if (nr == h->pipe) {
        /* Legacy pipe(2) has only one arg: pipefd. Create host pipe and inject
         * via ADDFD, same as the pipe2 path.
         */
        pid_t ppid = kbox_syscall_request_pid(req);
        uint64_t remote_pfd = kbox_syscall_request_arg(req, 0);
        if (remote_pfd == 0)
            return kbox_dispatch_errno(EFAULT);

        int host_pfds[2];
        if (pipe(host_pfds) < 0)
            return kbox_dispatch_errno(errno);

        int tfd0 = request_addfd(ctx, req, host_pfds[0], 0);
        if (tfd0 < 0) {
            close(host_pfds[0]);
            close(host_pfds[1]);
            return kbox_dispatch_errno(-tfd0);
        }
        int tfd1 = request_addfd(ctx, req, host_pfds[1], 0);
        if (tfd1 < 0) {
            close(host_pfds[0]);
            close(host_pfds[1]);
            return kbox_dispatch_errno(-tfd1);
        }
        close(host_pfds[0]);
        close(host_pfds[1]);

        int gfds[2] = {tfd0, tfd1};
        int pwrc = guest_mem_write(ctx, ppid, remote_pfd, gfds, sizeof(gfds));
        if (pwrc < 0)
            return kbox_dispatch_errno(-pwrc);
        return kbox_dispatch_value(0);
    }
    if (nr == h->symlinkat)
        return forward_symlinkat(req, ctx);
    if (nr == h->linkat)
        return forward_linkat(req, ctx);
    if (nr == h->utimensat)
        return forward_utimensat(req, ctx);
    if (nr == h->sendfile)
        return forward_sendfile(req, ctx);
    if (nr == h->copy_file_range)
        return kbox_dispatch_errno(ENOSYS);

    /* Process info. */

    if (nr == h->getpid)
        return kbox_dispatch_value(1);
    if (nr == h->getppid)
        return kbox_dispatch_value(0);
    if (nr == h->gettid)
        return kbox_dispatch_value(1);
    if (nr == h->setpgid)
        return kbox_dispatch_continue();
    if (nr == h->getpgid)
        return kbox_dispatch_continue();
    if (nr == h->getsid)
        return kbox_dispatch_continue();
    if (nr == h->setsid)
        return kbox_dispatch_continue();

    /* Time. */

    if (nr == h->clock_gettime)
        return forward_clock_gettime(req, ctx);
    if (nr == h->clock_getres)
        return forward_clock_getres(req, ctx);
    if (nr == h->gettimeofday)
        return forward_gettimeofday(req, ctx);

    /* Process lifecycle. */

    if (nr == h->umask)
        return forward_umask(req, ctx);
    if (nr == h->uname)
        return forward_uname(req, ctx);
    if (nr == h->brk)
        return kbox_dispatch_continue();
    if (nr == h->getrandom)
        return forward_getrandom(req, ctx);
    if (nr == h->syslog)
        return forward_syslog(req, ctx);
    if (nr == h->prctl)
        return forward_prctl(req, ctx);
    if (nr == h->wait4)
        return kbox_dispatch_continue();
    if (nr == h->waitid)
        return kbox_dispatch_continue();
    if (nr == h->exit)
        return kbox_dispatch_continue();
    if (nr == h->exit_group)
        return kbox_dispatch_continue();

    /* Signals (CONTINUE). */
    /* Signal disposition and masking are per-process host kernel state. */

    if (nr == h->rt_sigaction) {
        if (request_uses_trap_signals(req) &&
            kbox_syscall_trap_signal_is_reserved(
                (int) to_c_long_arg(kbox_syscall_request_arg(req, 0)))) {
            if (ctx->verbose) {
                fprintf(stderr,
                        "kbox: reserved SIGSYS handler change denied "
                        "(pid=%u source=%d)\n",
                        kbox_syscall_request_pid(req), req->source);
            }
            return kbox_dispatch_errno(EPERM);
        }
        {
            int signo = (int) to_c_long_arg(kbox_syscall_request_arg(req, 0));
            if (signo == 11 /* SIGSEGV */ || signo == 7 /* SIGBUS */)
                kbox_procmem_signal_changed();
        }
        return kbox_dispatch_continue(); /* signal handler registration */
    }
    if (nr == h->rt_sigprocmask) {
        if (request_uses_trap_signals(req)) {
            long how = to_c_long_arg(kbox_syscall_request_arg(req, 0));
            int blocks_reserved = request_blocks_reserved_sigsys(req, ctx);

            if (blocks_reserved < 0)
                return kbox_dispatch_errno(-blocks_reserved);
            if (how != SIG_UNBLOCK && blocks_reserved) {
                if (ctx->verbose) {
                    fprintf(stderr,
                            "kbox: reserved SIGSYS mask change denied "
                            "(pid=%u source=%d how=%ld)\n",
                            kbox_syscall_request_pid(req), req->source, how);
                }
                return kbox_dispatch_errno(EPERM);
            }
            return emulate_trap_rt_sigprocmask(req, ctx);
        }
        return kbox_dispatch_continue(); /* signal mask manipulation */
    }
    if (nr == h->rt_sigreturn)
        return kbox_dispatch_continue(); /* return from signal handler */
    if (nr == h->rt_sigpending) {
        if (request_uses_trap_signals(req))
            return emulate_trap_rt_sigpending(req, ctx);
        return kbox_dispatch_continue(); /* pending signal query */
    }
    if (nr == h->rt_sigaltstack)
        return kbox_dispatch_continue(); /* alternate signal stack */
    if (nr == h->setitimer)
        return kbox_dispatch_continue(); /* interval timer */
    if (nr == h->getitimer)
        return kbox_dispatch_continue(); /* query interval timer */
    if (h->alarm >= 0 && nr == h->alarm)
        return kbox_dispatch_continue(); /* alarm (not on aarch64) */

    /* Signal delivery (dispatch: PID validation). */
    /* kill/tgkill/tkill must go through dispatch (not BPF deny) because ash
     * needs them for job control. We validate the target PID belongs to the
     * guest process tree.  PID is in register args (no TOCTOU).
     */

    /* Accept the guest's virtual PID (1) as equivalent to the real host
     * PID. getpid/gettid return 1, so raise() calls tgkill(1, 1, sig) which
     * must reach the host kernel with the real PID. Also accept notif->pid
     * (the tracee's actual host PID from the seccomp notification).
     */
#define IS_GUEST_PID(p) \
    ((p) == ctx->child_pid || (p) == kbox_syscall_request_pid(req) || (p) == 1)

    if (nr == h->kill) {
        pid_t target = (pid_t) kbox_syscall_request_arg(req, 0);
        int sig = (int) kbox_syscall_request_arg(req, 1);
        if (!IS_GUEST_PID(target) && target != 0) {
            if (ctx->verbose)
                fprintf(stderr, "kbox: kill(%d) denied: not guest PID\n",
                        target);
            return kbox_dispatch_errno(EPERM);
        }
        /* Translate virtual PID to real PID.  In both seccomp and trap
         * mode, the guest sees itself as PID 1.  Route kill(1, sig) and
         * kill(0, sig) to the real child PID.
         */
        {
            pid_t real_target = ctx->child_pid;
            long ret = syscall(SYS_kill, real_target, sig);
            if (ret < 0)
                return kbox_dispatch_errno(errno);
            if (request_uses_trap_signals(req) &&
                real_target == ctx->child_pid &&
                trap_sigmask_contains_signal(sig))
                (void) kbox_syscall_trap_add_pending_signal(sig);
            return kbox_dispatch_value(0);
        }
    }
    if (nr == h->tgkill) {
        pid_t tgid = (pid_t) kbox_syscall_request_arg(req, 0);
        pid_t tid = (pid_t) kbox_syscall_request_arg(req, 1);
        int sig = (int) kbox_syscall_request_arg(req, 2);
        if (!IS_GUEST_PID(tgid)) {
            if (ctx->verbose)
                fprintf(stderr, "kbox: tgkill(%d) denied: not guest PID\n",
                        tgid);
            return kbox_dispatch_errno(EPERM);
        }
        /* Translate virtual PID/TID to real.  Both seccomp and trap modes
         * must emulate tgkill because the guest uses virtual PID 1.
         */
        {
            pid_t real_tgid = ctx->child_pid;
            pid_t real_tid = (tid == 1) ? kbox_syscall_request_pid(req) : tid;
            long ret = syscall(SYS_tgkill, real_tgid, real_tid, sig);
            if (ret < 0)
                return kbox_dispatch_errno(errno);
            if (request_uses_trap_signals(req) && real_tgid == ctx->child_pid &&
                real_tid == kbox_syscall_request_pid(req) &&
                trap_sigmask_contains_signal(sig))
                (void) kbox_syscall_trap_add_pending_signal(sig);
            return kbox_dispatch_value(0);
        }
    }
    if (nr == h->tkill) {
        pid_t target = (pid_t) kbox_syscall_request_arg(req, 0);
        int sig = (int) kbox_syscall_request_arg(req, 1);
        if (!IS_GUEST_PID(target)) {
            if (ctx->verbose)
                fprintf(stderr, "kbox: tkill(%d) denied: not guest PID\n",
                        target);
            return kbox_dispatch_errno(EPERM);
        }
        {
            pid_t real_tid =
                (target == 1) ? kbox_syscall_request_pid(req) : target;
            long ret = syscall(SYS_tkill, real_tid, sig);
            if (ret < 0)
                return kbox_dispatch_errno(errno);
            if (request_uses_trap_signals(req) &&
                real_tid == kbox_syscall_request_pid(req) &&
                trap_sigmask_contains_signal(sig))
                (void) kbox_syscall_trap_add_pending_signal(sig);
            return kbox_dispatch_value(0);
        }
    }
#undef IS_GUEST_PID
    if (nr == h->pidfd_send_signal) {
        /* pidfd_send_signal is rare; deny by default for now. */
        return kbox_dispatch_errno(EPERM);
    }

    /* Threading (CONTINUE). */
    /* Thread management is host kernel state; LKL is not involved. */

    if (nr == h->set_tid_address)
        return kbox_dispatch_continue(); /* set clear_child_tid pointer */
    if (nr == h->set_robust_list)
        return kbox_dispatch_continue(); /* robust futex list */
    if (nr == h->futex)
        return kbox_dispatch_continue(); /* fast userspace mutex */
    if (nr == h->clone3)
        return forward_clone3(req, ctx); /* sanitize namespace flags */
    if (nr == h->arch_prctl) {
        /* In trap/rewrite mode, arch_prctl(SET_FS) must be intercepted
         * to avoid overwriting kbox's TLS.  The SIGSYS handler swaps
         * FS on entry/exit; SET_FS updates the guest's saved FS base
         * so it takes effect when the handler returns.  GET_FS returns
         * the guest's saved FS base.  In seccomp mode, CONTINUE is fine
         * because the supervisor runs in a separate process.
         */
        if (request_uses_trap_signals(req)) {
            long subcmd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
            if (subcmd == 0x1002 /* ARCH_SET_FS */) {
                kbox_syscall_trap_set_guest_fs(
                    kbox_syscall_request_arg(req, 1));
                return kbox_dispatch_value(0);
            }
            if (subcmd == 0x1003 /* ARCH_GET_FS */) {
                uint64_t out_ptr = kbox_syscall_request_arg(req, 1);
                uint64_t fs = kbox_syscall_trap_get_guest_fs();
                if (out_ptr == 0)
                    return kbox_dispatch_errno(EFAULT);
                int wrc = guest_mem_write(ctx, kbox_syscall_request_pid(req),
                                          out_ptr, &fs, sizeof(fs));
                if (wrc < 0)
                    return kbox_dispatch_errno(-wrc);
                return kbox_dispatch_value(0);
            }
        }
        return kbox_dispatch_continue(); /* GS or seccomp mode */
    }
    if (nr == h->rseq)
        return kbox_dispatch_continue(); /* restartable sequences */
    if (nr == h->clone) {
        /* Legacy clone: flags are in args[0] directly (not a struct). */
        uint64_t cflags = kbox_syscall_request_arg(req, 0);
        if (cflags & CLONE_NEW_MASK) {
            if (ctx->verbose)
                fprintf(stderr,
                        "kbox: clone denied: namespace flags 0x%llx "
                        "(pid=%u)\n",
                        (unsigned long long) (cflags & CLONE_NEW_MASK),
                        kbox_syscall_request_pid(req));
            return kbox_dispatch_errno(EPERM);
        }
        /* In trap/rewrite mode, block thread creation (CLONE_THREAD).
         * The SIGSYS handler and shared LKL state are not thread-safe;
         * multi-threaded guests must use --syscall-mode=seccomp.
         */
        if ((cflags & CLONE_THREAD) && request_uses_trap_signals(req)) {
            if (ctx->verbose)
                fprintf(stderr,
                        "kbox: clone denied: CLONE_THREAD in trap/rewrite mode "
                        "(pid=%u, use --syscall-mode=seccomp)\n",
                        kbox_syscall_request_pid(req));
            return kbox_dispatch_errno(EPERM);
        }
        return kbox_dispatch_continue();
    }
    if (nr == h->fork)
        return kbox_dispatch_continue(); /* legacy fork */
    if (nr == h->vfork)
        return kbox_dispatch_continue(); /* legacy vfork */

    /* Memory mapping. */

    if (nr == h->mmap) {
        invalidate_translated_path_cache(ctx);
        return forward_mmap(req, ctx);
    }
    if (nr == h->munmap) {
        invalidate_translated_path_cache(ctx);
        return kbox_dispatch_continue(); /* unmap pages */
    }
    if (nr == h->mprotect) {
        invalidate_translated_path_cache(ctx);
        return forward_mprotect(req, ctx); /* W^X enforcement + CONTINUE */
    }
    if (nr == h->mremap) {
        invalidate_translated_path_cache(ctx);
        return kbox_dispatch_continue(); /* remap pages */
    }
    if (nr == h->membarrier)
        return kbox_dispatch_continue(); /* memory barrier (musl threads) */

    /* Scheduling (CONTINUE). */
    /* Scheduler ops are safe; RLIMIT_RTPRIO=0 prevents RT starvation. */

    if (nr == h->sched_yield)
        return kbox_dispatch_continue();
    if (nr == h->sched_setparam)
        return kbox_dispatch_continue();
    if (nr == h->sched_getparam)
        return kbox_dispatch_continue();
    if (nr == h->sched_setscheduler)
        return kbox_dispatch_continue();
    if (nr == h->sched_getscheduler)
        return kbox_dispatch_continue();
    if (nr == h->sched_get_priority_max)
        return kbox_dispatch_continue();
    if (nr == h->sched_get_priority_min)
        return kbox_dispatch_continue();
    if (nr == h->sched_setaffinity)
        return kbox_dispatch_continue();
    if (nr == h->sched_getaffinity)
        return kbox_dispatch_continue();

    /* Resource management. */

    /* prlimit64: GET ops are safe (read-only). SET ops on dangerous resources
     * (RLIMIT_NPROC, RLIMIT_NOFILE, RLIMIT_RTPRIO) are blocked to prevent the
     * guest from escaping resource limits.
     */
    if (nr == h->prlimit64) {
        uint64_t new_limit_ptr = kbox_syscall_request_arg(req, 2);
        if (new_limit_ptr == 0)
            return kbox_dispatch_continue(); /* GET only */
        /* SET operation: check which resource. */
        int resource = (int) kbox_syscall_request_arg(req, 1);
        /* Allow safe resources: RLIMIT_CORE(4), RLIMIT_AS(9), etc. */
        if (resource == 4 /* RLIMIT_CORE */ || resource == 9 /* RLIMIT_AS */)
            return kbox_dispatch_continue();
        if (ctx->verbose)
            fprintf(stderr, "kbox: prlimit64 SET resource=%d denied\n",
                    resource);
        return kbox_dispatch_errno(EPERM);
    }
    if (nr == h->madvise)
        return kbox_dispatch_continue(); /* memory advice */
    if (nr == h->getrlimit)
        return kbox_dispatch_continue(); /* read resource limits */
    if (nr == h->getrusage)
        return kbox_dispatch_continue(); /* read resource usage */

    /* I/O multiplexing (CONTINUE). */
    /* All polling/select variants are pure host kernel operations. */

    if (nr == h->epoll_create1)
        return kbox_dispatch_continue();
    if (nr == h->epoll_ctl)
        return kbox_dispatch_continue();
    if (nr == h->epoll_wait)
        return kbox_dispatch_continue();
    if (nr == h->epoll_pwait)
        return kbox_dispatch_continue();
    if (nr == h->ppoll)
        return kbox_dispatch_continue();
    if (nr == h->pselect6)
        return kbox_dispatch_continue();
    if (nr == h->poll)
        return kbox_dispatch_continue(); /* legacy poll (musl/busybox) */

    /* Sleep/timer (CONTINUE). */
    /* Time waiting is pure host kernel; no LKL involvement. */

    if (nr == h->nanosleep)
        return kbox_dispatch_continue();
    if (nr == h->clock_nanosleep)
        return kbox_dispatch_continue();
    if (nr == h->timerfd_create)
        return kbox_dispatch_continue();
    if (nr == h->timerfd_settime)
        return kbox_dispatch_continue();
    if (nr == h->timerfd_gettime)
        return kbox_dispatch_continue();
    if (nr == h->eventfd)
        return kbox_dispatch_continue();
    if (nr == h->eventfd2)
        return kbox_dispatch_continue();

    /* Filesystem info (CONTINUE/dispatch). */

    if (nr == h->statfs)
        return kbox_dispatch_continue(); /* filesystem stats */
    if (nr == h->fstatfs)
        return kbox_dispatch_continue(); /* filesystem stats by fd */
    if (nr == h->sysinfo)
        return kbox_dispatch_continue(); /* system info (busybox free) */

    /* readlink: takes path pointer (TOCTOU risk). Forward to LKL via readlinkat
     * instead of CONTINUE.
     */
    if (nr == h->readlink) {
        char path[4096];
        int ret = guest_mem_read_string(ctx, kbox_syscall_request_pid(req),
                                        kbox_syscall_request_arg(req, 0), path,
                                        sizeof(path));
        if (ret < 0)
            return kbox_dispatch_errno(-ret);
        long bufsiz = (long) kbox_syscall_request_arg(req, 2);
        char buf[4096];
        if (bufsiz > (long) sizeof(buf))
            bufsiz = (long) sizeof(buf);
        long lret =
            kbox_lkl_readlinkat(ctx->sysnrs, AT_FDCWD_LINUX, path, buf, bufsiz);
        if (lret < 0)
            return kbox_dispatch_from_lkl(lret);
        ret = guest_mem_write(ctx, kbox_syscall_request_pid(req),
                              kbox_syscall_request_arg(req, 1), buf,
                              (size_t) lret);
        if (ret < 0)
            return kbox_dispatch_errno(-ret);
        return kbox_dispatch_value(lret);
    }

    /* Exec (in-image binary extraction + pathname rewrite). */

    if (nr == h->execve)
        return forward_execve(req, ctx, 0);
    if (nr == h->execveat)
        return forward_execve(req, ctx, 1);

    /* Default: deny unknown syscalls. */
    if (ctx->verbose)
        fprintf(stderr, "kbox: DENY unknown syscall nr=%d (pid=%u)\n", nr,
                kbox_syscall_request_pid(req));
    return kbox_dispatch_errno(ENOSYS);
}

struct kbox_dispatch kbox_dispatch_syscall(struct kbox_supervisor_ctx *ctx,
                                           const void *notif_ptr)
{
    struct kbox_syscall_request req;

    if (kbox_syscall_request_from_notif(notif_ptr, &req) < 0)
        return kbox_dispatch_errno(EINVAL);
    return kbox_dispatch_request(ctx, &req);
}
