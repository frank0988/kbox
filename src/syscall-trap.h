/* SPDX-License-Identifier: MIT */
#ifndef KBOX_SYSCALL_TRAP_H
#define KBOX_SYSCALL_TRAP_H

#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>

#include "seccomp.h"
#include "syscall-trap-signal.h"

struct kbox_syscall_trap_runtime;

struct kbox_syscall_trap_ops {
    int (*execute)(struct kbox_syscall_trap_runtime *runtime,
                   const struct kbox_syscall_request *req,
                   struct kbox_dispatch *out);
};

struct kbox_syscall_trap_runtime {
    struct kbox_supervisor_ctx *ctx;
    const struct kbox_syscall_trap_ops *ops;
    struct sigaction old_sigsys;
    struct kbox_syscall_request last_request;
    struct kbox_dispatch last_dispatch;
    struct kbox_syscall_request pending_request;
    struct kbox_dispatch pending_dispatch;
    pid_t pid;
    int wake_fd;
    int owns_wake_fd;
    int service_stop;
    int service_running;
    pthread_t service_thread;
    int has_last_request;
    int has_last_dispatch;
    /* Cacheline-separated IPC flags: guest writes has_pending_request,
     * service thread writes has_pending_dispatch.  Separate cache lines
     * eliminate false sharing on x86_64 (~0.3-1us per call).
     */
    _Alignas(64) int has_pending_request;
    _Alignas(64) int has_pending_dispatch;
    void *active_ucontext;
    sigset_t emulated_pending;
    int installed;
    int sqpoll;
#if defined(__x86_64__)
    uint64_t host_fs_base;
    uint64_t guest_fs_base;
#endif
};

int kbox_syscall_regs_from_sigsys(const siginfo_t *info,
                                  const void *ucontext_ptr,
                                  struct kbox_syscall_regs *out);
int kbox_syscall_request_from_sigsys(struct kbox_syscall_request *out,
                                     pid_t pid,
                                     const siginfo_t *info,
                                     const void *ucontext_ptr,
                                     const struct kbox_guest_mem *guest_mem);
int kbox_syscall_trap_runtime_init(struct kbox_syscall_trap_runtime *runtime,
                                   struct kbox_supervisor_ctx *ctx,
                                   const struct kbox_syscall_trap_ops *ops);
void kbox_syscall_trap_runtime_set_wake_fd(
    struct kbox_syscall_trap_runtime *runtime,
    int wake_fd);
int kbox_syscall_trap_runtime_capture(struct kbox_syscall_trap_runtime *runtime,
                                      const struct kbox_syscall_request *req);
int kbox_syscall_trap_runtime_take_pending(
    struct kbox_syscall_trap_runtime *runtime,
    struct kbox_syscall_request *out);
int kbox_syscall_trap_runtime_complete(
    struct kbox_syscall_trap_runtime *runtime,
    const struct kbox_dispatch *dispatch);
int kbox_syscall_trap_runtime_take_dispatch(
    struct kbox_syscall_trap_runtime *runtime,
    struct kbox_dispatch *out);
int kbox_syscall_trap_active_dispatch(const struct kbox_syscall_request *req,
                                      struct kbox_dispatch *out);
pid_t kbox_syscall_trap_active_pid(void);
int kbox_syscall_trap_runtime_dispatch_pending(
    struct kbox_syscall_trap_runtime *runtime,
    struct kbox_dispatch *out);
int kbox_syscall_trap_runtime_service_start(
    struct kbox_syscall_trap_runtime *runtime);
int kbox_syscall_trap_runtime_service_stop(
    struct kbox_syscall_trap_runtime *runtime);
int kbox_syscall_trap_handle(struct kbox_syscall_trap_runtime *runtime,
                             const siginfo_t *info,
                             void *ucontext_ptr);
int kbox_syscall_dispatch_sigsys(struct kbox_supervisor_ctx *ctx,
                                 pid_t pid,
                                 const siginfo_t *info,
                                 void *ucontext_ptr);
int kbox_syscall_result_to_sigsys(void *ucontext_ptr,
                                  const struct kbox_dispatch *dispatch);
int kbox_syscall_trap_runtime_install(struct kbox_syscall_trap_runtime *runtime,
                                      struct kbox_supervisor_ctx *ctx);
void kbox_syscall_trap_runtime_uninstall(
    struct kbox_syscall_trap_runtime *runtime);
uint64_t kbox_syscall_trap_get_guest_fs(void);
void kbox_syscall_trap_set_guest_fs(uint64_t val);
int kbox_syscall_trap_get_sigmask(void *out, size_t len);
int kbox_syscall_trap_set_sigmask(const void *mask, size_t len);
int kbox_syscall_trap_get_pending(void *out, size_t len);
int kbox_syscall_trap_set_pending(const void *mask, size_t len);
int kbox_syscall_trap_add_pending_signal(int signo);

#endif /* KBOX_SYSCALL_TRAP_H */
