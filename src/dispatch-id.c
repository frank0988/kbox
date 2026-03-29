/* SPDX-License-Identifier: MIT */

/* Identity syscall handlers for the seccomp dispatch engine.
 *
 * UID, GID, supplementary groups, and umask operations. All LKL identity
 * calls go through kbox_lkl_* wrappers in lkl-wrap.h.
 */

#include <errno.h>
#include <stdint.h>
#include <sys/types.h>

#include "dispatch-internal.h"

/* Shared getresuid/getresgid implementation. The three getters retrieve the
 * real, effective, and saved IDs respectively. LKL has no separate saved ID,
 * so callers pass the effective getter for the saved slot.
 */

typedef long (*lkl_id_getter)(const struct kbox_sysnrs *);

static struct kbox_dispatch forward_getresid(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    lkl_id_getter get_real,
    lkl_id_getter get_effective,
    lkl_id_getter get_saved)
{
    pid_t pid = kbox_syscall_request_pid(req);
    lkl_id_getter getters[3] = {get_real, get_effective, get_saved};
    int i;

    for (i = 0; i < 3; i++) {
        uint64_t ptr = kbox_syscall_request_arg(req, i);
        if (ptr == 0)
            continue;
        long r = getters[i](ctx->sysnrs);
        if (r < 0)
            return kbox_dispatch_errno((int) (-r));
        unsigned val = (unsigned) r;
        int wrc = guest_mem_write(ctx, pid, ptr, &val, sizeof(val));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }
    return kbox_dispatch_value(0);
}

struct kbox_dispatch forward_getresuid(const struct kbox_syscall_request *req,
                                       struct kbox_supervisor_ctx *ctx)
{
    return forward_getresid(req, ctx, kbox_lkl_getuid, kbox_lkl_geteuid,
                            kbox_lkl_geteuid);
}

struct kbox_dispatch forward_getresgid(const struct kbox_syscall_request *req,
                                       struct kbox_supervisor_ctx *ctx)
{
    return forward_getresid(req, ctx, kbox_lkl_getgid, kbox_lkl_getegid,
                            kbox_lkl_getegid);
}

/* Shared override: write the same value to all three output pointers. */

static struct kbox_dispatch forward_getresid_override(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    unsigned id_val)
{
    pid_t pid = kbox_syscall_request_pid(req);
    int i;

    for (i = 0; i < 3; i++) {
        uint64_t ptr = kbox_syscall_request_arg(req, i);
        if (ptr != 0) {
            int wrc = guest_mem_write(ctx, pid, ptr, &id_val, sizeof(id_val));
            if (wrc < 0)
                return kbox_dispatch_errno(EIO);
        }
    }
    return kbox_dispatch_value(0);
}

struct kbox_dispatch forward_getresuid_override(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    uid_t uid)
{
    return forward_getresid_override(req, ctx, (unsigned) uid);
}

struct kbox_dispatch forward_getresgid_override(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    gid_t gid)
{
    return forward_getresid_override(req, ctx, (unsigned) gid);
}

struct kbox_dispatch forward_getgroups(const struct kbox_syscall_request *req,
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

struct kbox_dispatch forward_getgroups_override(
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

struct kbox_dispatch forward_setuid(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx)
{
    long uid = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    return kbox_dispatch_from_lkl(kbox_lkl_setuid(ctx->sysnrs, uid));
}

struct kbox_dispatch forward_setreuid(const struct kbox_syscall_request *req,
                                      struct kbox_supervisor_ctx *ctx)
{
    long ruid = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long euid = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    return kbox_dispatch_from_lkl(kbox_lkl_setreuid(ctx->sysnrs, ruid, euid));
}

struct kbox_dispatch forward_setresuid(const struct kbox_syscall_request *req,
                                       struct kbox_supervisor_ctx *ctx)
{
    long ruid = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long euid = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long suid = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    return kbox_dispatch_from_lkl(
        kbox_lkl_setresuid(ctx->sysnrs, ruid, euid, suid));
}

struct kbox_dispatch forward_setgid(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx)
{
    long gid = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    return kbox_dispatch_from_lkl(kbox_lkl_setgid(ctx->sysnrs, gid));
}

struct kbox_dispatch forward_setregid(const struct kbox_syscall_request *req,
                                      struct kbox_supervisor_ctx *ctx)
{
    long rgid = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long egid = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    return kbox_dispatch_from_lkl(kbox_lkl_setregid(ctx->sysnrs, rgid, egid));
}

struct kbox_dispatch forward_setresgid(const struct kbox_syscall_request *req,
                                       struct kbox_supervisor_ctx *ctx)
{
    long rgid = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long egid = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long sgid = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    return kbox_dispatch_from_lkl(
        kbox_lkl_setresgid(ctx->sysnrs, rgid, egid, sgid));
}

struct kbox_dispatch forward_setgroups(const struct kbox_syscall_request *req,
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

struct kbox_dispatch forward_setfsgid(const struct kbox_syscall_request *req,
                                      struct kbox_supervisor_ctx *ctx)
{
    long gid = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    return kbox_dispatch_from_lkl(kbox_lkl_setfsgid(ctx->sysnrs, gid));
}

/* Identity dispatch helpers.
 *
 * In host+root_identity mode, get* returns 0 and set* returns 0.
 * In host+override mode, get* returns the override value.
 * In host+neither mode, CONTINUE to host kernel.
 * In image mode, forward to LKL.
 */

/* Shared get-ID dispatcher. has_override + override_val avoid a sentinel
 * comparison that breaks when uid_t/gid_t is narrower than unsigned long.
 */
static struct kbox_dispatch dispatch_get_id(
    long (*lkl_func)(const struct kbox_sysnrs *),
    struct kbox_supervisor_ctx *ctx,
    int has_override,
    unsigned override_val)
{
    if (ctx->host_root) {
        if (ctx->root_identity)
            return kbox_dispatch_value(0);
        if (has_override)
            return kbox_dispatch_value((int64_t) override_val);
        return kbox_dispatch_continue();
    }
    return kbox_dispatch_from_lkl(lkl_func(ctx->sysnrs));
}

struct kbox_dispatch dispatch_get_uid(
    long (*lkl_func)(const struct kbox_sysnrs *),
    struct kbox_supervisor_ctx *ctx)
{
    int has = ctx->override_uid != (uid_t) -1;
    return dispatch_get_id(lkl_func, ctx, has, (unsigned) ctx->override_uid);
}

struct kbox_dispatch dispatch_get_gid(
    long (*lkl_func)(const struct kbox_sysnrs *),
    struct kbox_supervisor_ctx *ctx)
{
    int has = ctx->override_gid != (gid_t) -1;
    return dispatch_get_id(lkl_func, ctx, has, (unsigned) ctx->override_gid);
}

struct kbox_dispatch dispatch_set_id(
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

struct kbox_dispatch forward_umask(const struct kbox_syscall_request *req,
                                   struct kbox_supervisor_ctx *ctx)
{
    long mask = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long ret = kbox_lkl_umask(ctx->sysnrs, mask);
    return kbox_dispatch_from_lkl(ret);
}
