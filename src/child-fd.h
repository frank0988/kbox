/* SPDX-License-Identifier: MIT */
#ifndef KBOX_CHILD_FD_H
#define KBOX_CHILD_FD_H

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef __NR_pidfd_open
#if defined(__x86_64__) || defined(__aarch64__)
#define __NR_pidfd_open 434
#endif
#endif

#ifndef __NR_pidfd_getfd
#if defined(__x86_64__) || defined(__aarch64__)
#define __NR_pidfd_getfd 438
#endif
#endif

#if defined(__NR_pidfd_open) && defined(__NR_pidfd_getfd)
#define KBOX_CHILD_FD_HAVE_PIDFD_SYSCALLS 1
#else
#define KBOX_CHILD_FD_HAVE_PIDFD_SYSCALLS 0
#endif

static inline int kbox_child_fd_pidfd_open(pid_t pid)
{
#if KBOX_CHILD_FD_HAVE_PIDFD_SYSCALLS
    long ret = syscall(__NR_pidfd_open, pid, 0);

    if (ret < 0)
        return -1;
    return (int) ret;
#else
    (void) pid;
    errno = ENOSYS;
    return -1;
#endif
}

static inline int kbox_child_fd_pidfd_getfd(int pidfd, int targetfd)
{
#if KBOX_CHILD_FD_HAVE_PIDFD_SYSCALLS
    long ret = syscall(__NR_pidfd_getfd, pidfd, targetfd, 0);

    if (ret < 0)
        return -1;
    return (int) ret;
#else
    (void) pidfd;
    (void) targetfd;
    errno = ENOSYS;
    return -1;
#endif
}

static inline int kbox_child_fd_dup_via_pidfd(pid_t pid, int targetfd)
{
    int pidfd;
    int dup_fd;

    pidfd = kbox_child_fd_pidfd_open(pid);
    if (pidfd < 0)
        return -1;

    dup_fd = kbox_child_fd_pidfd_getfd(pidfd, targetfd);
    {
        int saved_errno = dup_fd < 0 ? errno : 0;
        close(pidfd);
        if (dup_fd < 0)
            errno = saved_errno;
    }
    return dup_fd;
}

static inline int kbox_child_fd_dup_via_proc(pid_t pid, int targetfd)
{
    char path[64];
    int n;

    n = snprintf(path, sizeof(path), "/proc/%ld/fd/%d", (long) pid, targetfd);
    if (n < 0 || (size_t) n >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    return open(path, O_CLOEXEC);
}

static inline int kbox_child_fd_dup(pid_t pid, int targetfd)
{
    int dup_fd;
    int saved_errno;

    if (pid <= 0 || targetfd < 0) {
        errno = EINVAL;
        return -1;
    }

    dup_fd = kbox_child_fd_dup_via_pidfd(pid, targetfd);
    if (dup_fd >= 0)
        return dup_fd;

    saved_errno = errno;
    if (saved_errno != ENOSYS) {
        errno = saved_errno;
        return -1;
    }

    return kbox_child_fd_dup_via_proc(pid, targetfd);
}

#endif /* KBOX_CHILD_FD_H */
