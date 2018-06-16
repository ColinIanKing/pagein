/*
 * Copyright (C) 2016-2018 Canonical, Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <dirent.h>
#include <ctype.h>
#include <setjmp.h>
#include <signal.h>

#define APP_NAME		"pagein"
#define PAGE_4K			(4096)

#define STACK_ALIGNMENT		(64)

#define OPT_VERBOSE		(0x00000001)
#define OPT_ALL			(0x00000002)
#define OPT_BY_PID		(0x00000004)

#define GOT_MEMFREE		(0x01)
#define GOT_SWAPFREE		(0x02)
#define GOT_ALL			(GOT_MEMFREE | GOT_SWAPFREE)

static uint16_t		opt_flags;
static sigjmp_buf 	jmp_env;

static void sigsegv_handler(int sig)
{
	static bool faulted = false;

	(void)sig;

	if (!faulted) {
		faulted = true;		/* Don't double fault */
		siglongjmp(jmp_env, 1);
	}
}

/*
 *  align_address
 *	align address to alignment, alignment MUST be a power of 2
 */
static inline void *align_address(const void *addr, const size_t alignment)
{
	const uintptr_t uintptr =
		((uintptr_t)addr + alignment) & ~(alignment - 1);

	return (void *)uintptr;
}

/*
 *  get_page_size()
 *	get page size
 */
static inline int32_t get_page_size(void)
{
	int32_t page_size;
#ifdef _SC_PAGESIZE
	static int32_t sz;	/* static noclobber */

	sz = sysconf(_SC_PAGESIZE);
	page_size = (sz <= 0) ? PAGE_4K : sz;
#else
	page_size = PAGE_4K;
#endif
	return page_size;
}

/*
 *  get_memstats()
 *	get some pertinent memory statistics from /proc/meminfo
 */
static int get_memstats(int64_t *const memfree, int64_t *const swapfree)
{
	FILE *fp;
	char buffer[4096];
	uint8_t got = 0;

	*memfree = 0;
	*swapfree = 0;

	fp = fopen("/proc/meminfo", "r");
	if (!fp)
		return -errno;

	while (fgets(buffer, sizeof(buffer), fp)) {
		if ((strstr(buffer, "MemFree:")) &&
		    (sscanf(buffer, "%*s %" SCNd64, memfree) == 1)) {
			got |= GOT_MEMFREE;
			continue;
		}
		if ((strstr(buffer, "SwapFree:")) &&
		    (sscanf(buffer, "%*s %" SCNd64, swapfree) == 1)) {
			got |= GOT_SWAPFREE;
		}
		if ((got & GOT_ALL) == GOT_ALL)
			break;
	}

	(void)fclose(fp);
	return 0;
}

/*
 *  show_help()
 *	show command help info
 */
static void show_help(void)
{
	(void)printf(APP_NAME ":\n");
	(void)printf("Usage: " APP_NAME " [OPTION [ARG]]\n");
	(void)printf("-a\tpage in pages in all processes\n");
	(void)printf("-h\tshow help\n");
	(void)printf("-p pid\tpull in pages on specified process\n");
	(void)printf("-v\tverbose mode\n");
	(void)printf("Note: to page in all processes, run with root privilege\n");
}

/*
 *  pagein_proc()
 *	try to force page in pages for a specific process
 */
static int pagein_proc(
	const int32_t page_size,
	const pid_t pid,
	int32_t *const procs,
	int32_t *const kthreads,
	int64_t *const total_pages_touched)
{
	char path[PATH_MAX];
	char buffer[4096];
	int fdmem, rc = 0, ret;
	FILE *fpmap;
	size_t pages = 0, pages_touched = 0;
	bool has_maps = false;

	if (pid == getpid())
		return 0;

	(void)snprintf(path, sizeof(path), "/proc/%d/mem", pid);
	fdmem = open(path, O_RDONLY);
	if (fdmem < 0) {
		rc = -errno;
		goto err_ret;
	}

	(void)snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	fpmap = fopen(path, "r");
	if (!fpmap) {
		rc = -errno;
		goto err_close_fdmem;
	}

	ret = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
	if (ret < 0) {
		rc = -errno;
		goto err_close_all;
	}

	(void)waitpid(pid, NULL, 0);

	/*
	 * Look for field 0060b000-0060c000 r--p 0000b000 08:01 1901726
	 */
	while (fgets(buffer, sizeof(buffer), fpmap)) {
		uint64_t begin, end, len;
		uintptr_t off;
		char tmppath[1024];
		char prot[5];

		if (sscanf(buffer, "%" SCNx64 "-%" SCNx64
			   " %5s %*x %*x:%*x %*d %1023s", &begin, &end, prot, tmppath) != 4)
			continue;
		len = end - begin;

		if ((begin >= end) || (len == 0))
			continue;

		has_maps = true;

		for (off = begin; off < end; off += page_size, pages++) {
			unsigned long data;
			off_t pos;

			(void)ptrace(PTRACE_PEEKDATA, pid, (void *)off, &data);
			pos = lseek(fdmem, (off_t)off, SEEK_SET);
			if (pos == (off_t)off) {
				size_t sz;

				sz = read(fdmem, &data, sizeof data);
				(void)sz;
			}

			pages_touched++;
		}
	}
	(void)ptrace(PTRACE_DETACH, pid, NULL, NULL);

	/*
	 *  Kernel threads don't have maps, so don't
	 *  count these in the stats
	 */
	if (has_maps) {
		*procs += 1;
		*total_pages_touched += pages_touched;
	} else {
		*kthreads += 1;
	}

	if (opt_flags & OPT_VERBOSE) {
		(void)printf("PID:%6d, %12zu pages, %12" PRId64 " pages touched\r", pid, pages,
			*total_pages_touched);
		(void)fflush(stdout);
	}

err_close_all:
	(void)fclose(fpmap);
err_close_fdmem:
	(void)close(fdmem);
err_ret:
	return rc;
}

/*
 *  pagein_all_procs()
 *	attempt to page in all processes
 */
static inline int pagein_all_procs(
	const int32_t page_size,
	int32_t *const procs,
	int32_t *const kthreads,
	int32_t *const total_procs,
	int64_t *const total_pages_touched)
{
	DIR *dp;
	struct dirent *d;

	dp = opendir("/proc");
	if (!dp)
		return -1;

	while ((d = readdir(dp)) != NULL) {
		pid_t pid;

		if (isdigit(d->d_name[0]) &&
                    sscanf(d->d_name, "%d", &pid) == 1) {
			*total_procs += 1;
			pagein_proc(page_size, pid, procs, kthreads,
				total_pages_touched);
		}
	}

	(void)closedir(dp);

	return 0;
}

int main(int argc, char **argv)
{
	int64_t memfree_begin, memfree_end;
	int64_t swapfree_begin, swapfree_end;
	int64_t delta;
	int64_t total_pages_touched = 0ULL;
	static int32_t total_procs = 0;		/* static noclobber */
	int32_t procs = 0, kthreads = 0;
	const int32_t page_size = get_page_size();
	const int32_t scale = page_size / 1024;
	static pid_t pid = -1;			/* static noclobber */
	struct rusage usage;
	struct sigaction action;
	stack_t ss;
	uint8_t	stack[SIGSTKSZ + STACK_ALIGNMENT];

	for (;;) {
		int c = getopt(argc, argv, "ahp:v");
		if (c == -1)
			break;

		switch (c) {
		case 'a':
			opt_flags |= OPT_ALL;
			break;
		case 'h':
			show_help();
			exit(EXIT_SUCCESS);
			break;
		case 'p':
			opt_flags |= OPT_BY_PID;
			pid = atoi(optarg);
			if (pid < 1) {
				(void)fprintf(stderr, "bad pid: %d\n", pid);
				exit(EXIT_FAILURE);
			}
			break;
		case 'v':
			opt_flags |= OPT_VERBOSE;
			break;
		default:
			show_help();
			exit(EXIT_FAILURE);
		}
	}

	if ((opt_flags & (OPT_ALL | OPT_BY_PID)) ==
		(OPT_ALL | OPT_BY_PID)) {
		(void)fprintf(stderr, "must not use -a and -p options together\n");
		exit(EXIT_FAILURE);
	}
	if ((opt_flags & (OPT_ALL | OPT_BY_PID)) == 0) {
		(void)fprintf(stderr, "must use one of -a or -p, use -h for more details\n");
		exit(EXIT_FAILURE);
	}

	if (sigsetjmp(jmp_env, 1) == 1) {
		(void)printf("Aborted early, hit a page fault\n");
		goto finish;
	}

	ss.ss_sp = align_address(&stack, STACK_ALIGNMENT);
	ss.ss_size = SIGSTKSZ;
	ss.ss_flags = 0;
	if (sigaltstack(&ss, NULL) < 0) {
		(void)fprintf(stderr, "cannot set sigaltstack stack\n");
		exit(EXIT_FAILURE);
	}
	(void)memset(&action, 0, sizeof(action));
	(void)sigemptyset(&action.sa_mask);
	action.sa_handler = sigsegv_handler;
	action.sa_flags = SA_ONSTACK;

	if (sigaction(SIGSEGV, &action, NULL) < 0) {
		(void)fprintf(stderr, "cannot set signal handler\n");
		exit(EXIT_FAILURE);
	}
		
	get_memstats(&memfree_begin, &swapfree_begin);
	if (opt_flags & OPT_ALL)
		pagein_all_procs(page_size, &procs, &kthreads, &total_procs, &total_pages_touched);

	if (opt_flags & OPT_BY_PID) {
		int ret;

		ret = pagein_proc(page_size, pid, &procs, &kthreads,
			&total_pages_touched);
		if (ret < 0) {
			(void)fprintf(stderr, "cannot page in PID %d errno = %d (%s)\n",
				pid, -ret, strerror(-ret));
			(void)fprintf(stderr, "  Note: this is normally because of ptrace PTRACE_MODE_ATTACH_FSCREDS access\n");
			(void)fprintf(stderr, "  mode failure of pagein. pagein needs to be run with the CAP_SYS_PTRACE\n");
			(void)fprintf(stderr, "  capability (for example, run pagein as root).\n");
			exit(EXIT_FAILURE);
		}
	}

	get_memstats(&memfree_end, &swapfree_end);
	if (opt_flags & OPT_VERBOSE)
		(void)printf("%-60.60s\r", "");

finish:
	if (opt_flags & OPT_ALL) {
		(void)printf("Processes scanned:     %" PRIu32 "\n", total_procs);
		(void)printf("Kernel threads:        %" PRIu32 " (skipped)\n", kthreads);
		(void)printf("Processes touched:     %" PRIu32 "\n", procs);
	}
	(void)printf("Pages touched:         %" PRIu64 "\n", total_pages_touched);
	delta = memfree_begin - memfree_end;
	(void)printf("Free memory decrease:  %" PRId64 "K (%" PRId64 " pages)\n",
		delta, delta / scale);
	delta = swapfree_begin - swapfree_end;
	(void)printf("Swap memory decrease:  %" PRId64 "K (%" PRId64 " pages)\n",
		delta, delta / scale);
	if (getrusage(RUSAGE_SELF, &usage) == 0) {
		(void)printf("Page faults major:     %lu\n", usage.ru_majflt);
		(void)printf("Page faults minor:     %lu\n", usage.ru_minflt);
		(void)printf("Swaps:                 %lu\n", usage.ru_nswap);
	}

	return EXIT_SUCCESS;
}
