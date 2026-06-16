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
#else

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

	memset(stack_buf, 0, sizeof(stack_buf));

	if (disable_system_calls((worker_st *)stack_buf) != 0) {
		fprintf(stderr, "disable_system_calls failed\n");
		return 1;
	}

	map = mmap(NULL, (size_t)page_size, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (map == MAP_FAILED) {
		perror("mmap");
		return 1;
	}

	errno = 0;
	ret = checked_syscall(
		"madvise",
		syscall(
#ifdef SYS_madvise
			SYS_madvise,
#else
			__NR_madvise,
#endif
			map, (size_t)page_size, MADV_DONTNEED));
	if (ret < 0 && errno == ENOSYS)
		return 1;

	errno = 0;
	remapped = checked_syscall(
		"mremap",
		syscall(
#ifdef SYS_mremap
			SYS_mremap,
#else
			__NR_mremap,
#endif
			map, (size_t)page_size, (size_t)page_size, 0));
	if (remapped < 0 && errno == ENOSYS)
		return 1;
	if (remapped >= 0)
		map = (void *)remapped;

	errno = 0;
	ret = checked_syscall(
		"munmap",
		syscall(
#ifdef SYS_munmap
			SYS_munmap,
#else
			__NR_munmap,
#endif
			map, (size_t)page_size));
	if (ret < 0 && errno == ENOSYS)
		return 1;

	return 0;
}

#endif
