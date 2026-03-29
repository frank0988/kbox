#ifndef KBOX_COMPILER_H
#define KBOX_COMPILER_H

/* Normalize compiler feature detection across GCC and Clang. */
#if defined(__has_feature)
#define KBOX_HAS_FEATURE(x) __has_feature(x)
#else
#define KBOX_HAS_FEATURE(x) 0
#endif

#if defined(__SANITIZE_ADDRESS__) || KBOX_HAS_FEATURE(address_sanitizer)
#define KBOX_HAS_ASAN 1
#else
#define KBOX_HAS_ASAN 0
#endif

#endif
