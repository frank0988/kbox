/* SPDX-License-Identifier: MIT */

#ifndef KBOX_PROCMEM_H
#define KBOX_PROCMEM_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "lkl-wrap.h"

struct kbox_guest_mem;

struct kbox_guest_mem_ops {
    int (*read)(const struct kbox_guest_mem *guest,
                uint64_t remote_addr,
                void *out,
                size_t len);
    int (*write)(const struct kbox_guest_mem *guest,
                 uint64_t remote_addr,
                 const void *in,
                 size_t len);
    int (*write_force)(const struct kbox_guest_mem *guest,
                       uint64_t remote_addr,
                       const void *in,
                       size_t len);
    int (*read_string)(const struct kbox_guest_mem *guest,
                       uint64_t remote_addr,
                       char *buf,
                       size_t max_len);
    int (*read_open_how)(const struct kbox_guest_mem *guest,
                         uint64_t remote_addr,
                         uint64_t size,
                         struct kbox_open_how *out);
};

struct kbox_guest_mem {
    const struct kbox_guest_mem_ops *ops;
    uintptr_t opaque;
};

extern const struct kbox_guest_mem_ops kbox_process_vm_guest_mem_ops;
extern const struct kbox_guest_mem_ops kbox_current_guest_mem_ops;

int kbox_vm_read(pid_t pid, uint64_t remote_addr, void *out, size_t len);
int kbox_vm_write(pid_t pid, uint64_t remote_addr, const void *in, size_t len);
int kbox_vm_write_force(pid_t pid,
                        uint64_t remote_addr,
                        const void *in,
                        size_t len);
int kbox_vm_read_string(pid_t pid,
                        uint64_t remote_addr,
                        char *buf,
                        size_t max_len);
int kbox_vm_read_open_how(pid_t pid,
                          uint64_t remote_addr,
                          uint64_t size,
                          struct kbox_open_how *out);
int kbox_guest_mem_read(const struct kbox_guest_mem *guest,
                        uint64_t remote_addr,
                        void *out,
                        size_t len);
int kbox_guest_mem_write(const struct kbox_guest_mem *guest,
                         uint64_t remote_addr,
                         const void *in,
                         size_t len);
int kbox_guest_mem_write_force(const struct kbox_guest_mem *guest,
                               uint64_t remote_addr,
                               const void *in,
                               size_t len);
int kbox_guest_mem_read_string(const struct kbox_guest_mem *guest,
                               uint64_t remote_addr,
                               char *buf,
                               size_t max_len);
int kbox_guest_mem_read_open_how(const struct kbox_guest_mem *guest,
                                 uint64_t remote_addr,
                                 uint64_t size,
                                 struct kbox_open_how *out);
int kbox_current_read(uint64_t remote_addr, void *out, size_t len);
int kbox_current_write(uint64_t remote_addr, const void *in, size_t len);
int kbox_current_write_force(uint64_t remote_addr, const void *in, size_t len);
int kbox_current_read_string(uint64_t remote_addr, char *buf, size_t max_len);
int kbox_current_read_open_how(uint64_t remote_addr,
                               uint64_t size,
                               struct kbox_open_how *out);

/* Notify the fault-recovery subsystem that the guest changed SIGSEGV or
 * SIGBUS disposition via rt_sigaction.  The next safe_memcpy call will
 * reinstall kbox's handler.
 */
void kbox_procmem_signal_changed(void);

#endif /* KBOX_PROCMEM_H */
