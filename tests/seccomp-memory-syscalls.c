/*
 * Verify that the worker seccomp filter allows allocator-related memory
 * syscalls that are used by musl under load.
 *
 * The regression in #749 was not that the syscalls behaved incorrectly, but
 * that isolated workers received ENOSYS from seccomp for munmap/mremap/
 * madvise. This test exercises the worker filter directly and fails if any of
 * those syscalls is translated to ENOSYS after the filter is installed.
 */

#include <config.h>

#ifndef __linux__
int main(void)
{
	return 77; /* skip on non-Linux */
}
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
int main(void)
{
	return 77; /* seccomp filter is intentionally incompatible with ASAN */
}
#else
#define SECCOMP_MEMORY_TEST_ENABLED 1
#endif
#elif defined(__SANITIZE_ADDRESS__)
int main(void)
{
	return 77; /* seccomp filter is intentionally incompatible with ASAN */
}
#else
#define SECCOMP_MEMORY_TEST_ENABLED 1
#endif

#ifdef SECCOMP_MEMORY_TEST_ENABLED

#include <assert.h>
#include <errno.h>
#include <seccomp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

typedef struct worker_st worker_st;

int disable_system_calls(worker_st *ws);

void _oclog(const worker_st *ws, int priority, const char *fmt, ...)
{
	(void)ws;
	(void)priority;
	(void)fmt;
}

static long checked_syscall(const char *name, long ret)
{
	if (ret == -1 && errno == ENOSYS) {
		fprintf(stderr, "%s blocked by seccomp (ENOSYS)\n", name);
		return -1;
	}
	return ret;
}

int main(void)
{
	char stack_buf[8192];
	long syscall_nr;
	long ret;
	void *map;
	long remapped;
	int page_size;

#if !defined(SYS_madvise) && !defined(__NR_madvise)
	return 77;
#endif
#if !defined(SYS_mremap) && !defined(__NR_mremap)
	return 77;
#endif
#if !defined(SYS_munmap) && !defined(__NR_munmap)
	return 77;
#endif

	page_size = getpagesize();
	assert(page_size > 0);

	map = mmap(NULL, (size_t)page_size, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (map == MAP_FAILED) {
		perror("mmap");
		return 1;
	}

	memset(stack_buf, 0, sizeof(stack_buf));

	if (disable_system_calls((worker_st *)stack_buf) != 0) {
		fprintf(stderr, "disable_system_calls failed\n");
		munmap(map, (size_t)page_size);
		return 1;
	}

#ifdef SYS_madvise
	syscall_nr = SYS_madvise;
#else
	syscall_nr = __NR_madvise;
#endif
	errno = 0;
	ret = syscall(syscall_nr, map, (size_t)page_size, MADV_DONTNEED);
	ret = checked_syscall("madvise", ret);
	if (ret < 0 && errno == ENOSYS)
		return 1;

#ifdef SYS_mremap
	syscall_nr = SYS_mremap;
#else
	syscall_nr = __NR_mremap;
#endif
	errno = 0;
	remapped = syscall(syscall_nr, map, (size_t)page_size,
			   (size_t)page_size, 0);
	remapped = checked_syscall("mremap", remapped);
	if (remapped < 0 && errno == ENOSYS)
		return 1;
	if (remapped >= 0)
		map = (void *)remapped;

#ifdef SYS_munmap
	syscall_nr = SYS_munmap;
#else
	syscall_nr = __NR_munmap;
#endif
	errno = 0;
	ret = syscall(syscall_nr, map, (size_t)page_size);
	ret = checked_syscall("munmap", ret);
	if (ret < 0 && errno == ENOSYS)
		return 1;

	return 0;
}

#endif
