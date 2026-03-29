/* SPDX-License-Identifier: MIT */

#include <errno.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string.h>

#include "procmem.h"
#include "test-runner.h"

static void test_current_guest_mem_read_write(void)
{
    char buf[16] = "hello";
    char out[16];

    memset(out, 0, sizeof(out));
    ASSERT_EQ(kbox_current_read((uint64_t) (uintptr_t) buf, out, 6), 0);
    ASSERT_STREQ(out, "hello");

    ASSERT_EQ(kbox_current_write((uint64_t) (uintptr_t) buf, "world", 6), 0);
    ASSERT_STREQ(buf, "world");
}

static void test_current_guest_mem_read_string(void)
{
    char buf[16];
    const char *src = "abc";

    memset(buf, 0, sizeof(buf));
    ASSERT_EQ(
        kbox_current_read_string((uint64_t) (uintptr_t) src, buf, sizeof(buf)),
        3);
    ASSERT_STREQ(buf, "abc");
}

static void test_current_guest_mem_ops_wrapper(void)
{
    char value[8] = "xyz";
    char out[8];
    struct kbox_guest_mem guest = {
        .ops = &kbox_current_guest_mem_ops,
        .opaque = 0,
    };

    memset(out, 0, sizeof(out));
    ASSERT_EQ(kbox_guest_mem_read(&guest, (uint64_t) (uintptr_t) value, out, 4),
              0);
    ASSERT_STREQ(out, "xyz");
}

static void test_current_guest_mem_rejects_bad_pointer(void)
{
    char out[8];

    ASSERT_EQ(kbox_current_read(0, out, sizeof(out)), -EFAULT);
    ASSERT_EQ(kbox_current_write(0, "x", 1), -EFAULT);
    ASSERT_EQ(kbox_current_read_string(0, out, sizeof(out)), -EFAULT);
    ASSERT_EQ(
        kbox_current_read_string((uint64_t) (uintptr_t) out, NULL, sizeof(out)),
        -EFAULT);
}

static void test_current_guest_mem_force_write_cross_page(void)
{
    long page_size = sysconf(_SC_PAGESIZE);
    char verify[4];
    char *mapping;

    ASSERT_TRUE(page_size > 0);
    mapping = mmap(NULL, (size_t) page_size * 2, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_NE(mapping, MAP_FAILED);

    memcpy(mapping + page_size - 2, "xxxx", 4);
    ASSERT_EQ(mprotect(mapping, (size_t) page_size * 2, PROT_READ), 0);
    ASSERT_EQ(kbox_current_write_force(
                  (uint64_t) (uintptr_t) (mapping + page_size - 2), "ABCD", 4),
              0);
    ASSERT_EQ(
        kbox_current_read((uint64_t) (uintptr_t) (mapping + page_size - 2),
                          verify, sizeof(verify)),
        0);
    ASSERT_EQ(memcmp(verify, "ABCD", 4), 0);
    ASSERT_EQ(munmap(mapping, (size_t) page_size * 2), 0);
}

static void test_current_guest_mem_unmapped_pointer_returns_error(void)
{
    long page_size = sysconf(_SC_PAGESIZE);
    char *mapping;
    pid_t pid;
    int status = 0;

    ASSERT_TRUE(page_size > 0);
    mapping = mmap(NULL, (size_t) page_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_NE(mapping, MAP_FAILED);
    ASSERT_EQ(munmap(mapping, (size_t) page_size), 0);

    pid = fork();
    ASSERT_TRUE(pid >= 0);
    if (pid == 0) {
        char out[4];
        int rc =
            kbox_current_read((uint64_t) (uintptr_t) mapping, out, sizeof(out));

        _exit(rc < 0 ? 0 : 1);
    }

    ASSERT_EQ(waitpid(pid, &status, 0), pid);
    ASSERT_TRUE(WIFEXITED(status));
    ASSERT_EQ(WEXITSTATUS(status), 0);
}

static void test_vm_write_force_rejects_bad_pointer(void)
{
    ASSERT_EQ(kbox_vm_write_force(getpid(), 0, "x", 1), -EFAULT);
    ASSERT_EQ(kbox_vm_write_force(getpid(), 1, NULL, 1), -EFAULT);
    ASSERT_EQ(kbox_vm_write_force(getpid(), 0, NULL, 0), 0);
}

void test_procmem_init(void)
{
    TEST_REGISTER(test_current_guest_mem_read_write);
    TEST_REGISTER(test_current_guest_mem_read_string);
    TEST_REGISTER(test_current_guest_mem_ops_wrapper);
    TEST_REGISTER(test_current_guest_mem_rejects_bad_pointer);
    TEST_REGISTER(test_current_guest_mem_force_write_cross_page);
    TEST_REGISTER(test_current_guest_mem_unmapped_pointer_returns_error);
    TEST_REGISTER(test_vm_write_force_rejects_bad_pointer);
}
