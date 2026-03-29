/* SPDX-License-Identifier: MIT */
#ifndef KBOX_SHADOW_FD_H
#define KBOX_SHADOW_FD_H

struct kbox_sysnrs;

#define KBOX_SHADOW_MAX_SIZE (256L * 1024 * 1024)

int kbox_shadow_create(const struct kbox_sysnrs *s, long lkl_fd);
int kbox_shadow_seal(int memfd);

#endif /* KBOX_SHADOW_FD_H */
