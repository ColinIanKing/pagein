#include <stdio.h>
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
#include <sys/wait.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <dirent.h>
#include <ctype.h>

#define APP_NAME		"pagein"
#define PAGE_4K			(4096)

#define OPT_VERBOSE		(0x00000001)
#define OPT_ALL			(0x00000002)
#define OPT_BY_PID		(0x00000004)

#define GOT_MEMFREE		(0x01)
#define GOT_SWAPFREE		(0x02)
#define GOT_ALL			(GOT_MEMFREE | GOT_SWAPFREE)

static uint16_t		opt_flags = 0;

/*
 *  get_pagesize()
 *	get pagesize
 */
static size_t get_pagesize(void)
{
#ifdef _SC_PAGESIZE
	long sz;
#endif
	static size_t page_size = 0;
	if (page_size > 0)
		return page_size;

#ifdef _SC_PAGESIZE
	sz = sysconf(_SC_PAGESIZE);
	page_size = (sz <= 0) ? PAGE_4K : (size_t)sz;
#else
	page_size = PAGE_4K;
#endif
	return page_size;
}

/*
 *  get_memstats()
 *	get some pertinent memory statistics from /proc/meminfo
 */
static int get_memstats(int64_t *memfree, int64_t *swapfree)
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
		    (sscanf(buffer, "%*s %" SCNu64, memfree) == 1)) {
			got |= GOT_MEMFREE;
			continue;
		}
		if ((strstr(buffer, "SwapFree:")) &&
		    (sscanf(buffer, "%*s %" SCNu64, swapfree) == 1)) {
			got |= GOT_SWAPFREE;
		}
		if ((got & GOT_ALL) == GOT_ALL)
			break;
	}

	fclose(fp);
	return 0;
}

/*
 *  show_help()
 *	show command help info
 */
static void show_help(void)
{
	printf(APP_NAME ":\n");
	printf("Usage: " APP_NAME " [OPTION [ARG]]\n");
	printf("-a\tpage in pages in all processes\n");
	printf("-h\tshow help\n");
	printf("-v\tverbose mode\n");
	printf("-p pid\tpull in pages on specified process\n");
	printf("Note: to page in all processes, run with root privilege\n");

}

/*
 *  pagein_proc()
 *	try to force page in pages for a specific process
 */
static int pagein_proc(
	const pid_t pid,
	const int64_t swapfree_begin,
	int32_t *const procs,
	int64_t *const total_pages_touched)
{
	char path[PATH_MAX];
	char buffer[4096];
	int fdmem;
	FILE *fpmap;
	off_t begin, end;
	size_t page_size = get_pagesize();
	size_t pages = 0, pages_touched = 0;
	bool has_maps = false;

	snprintf(path, sizeof(path), "/proc/%d/mem", pid);
	fdmem = open(path, O_RDONLY);
	if (fdmem < 0)
		return -errno;

	snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	fpmap = fopen(path, "r");
	if (!fpmap) {
		close(fdmem);
		return -errno;
	}

	/*
	 * Look for field 0060b000-0060c000 r--p 0000b000 08:01 1901726
	 */
	while (fgets(buffer, sizeof(buffer), fpmap)) {
		int64_t memfree, swapfree;
		off_t off;
		uint8_t byte;
		if (sscanf(buffer, "%" SCNx64 "-%" SCNx64, &begin, &end) != 2)
			continue;

		has_maps = true;
		ptrace(PTRACE_ATTACH, pid, NULL, NULL);
		waitpid(pid, NULL, 0);
		for (off = begin; off < end; off += page_size, pages++) {
			if (lseek(fdmem, off, SEEK_SET) == (off_t)-1)
				continue;
			if (read(fdmem, &byte, sizeof(byte)) == sizeof(byte))
				pages_touched++;
		}
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
		if (!get_memstats(&memfree, &swapfree) &&
		    swapfree < swapfree_begin) {
			break;
		}
	}

	/*
	 *  Kernel threads don't have maps, so don't
	 *  count these in the stats
	 */
	if (has_maps) {
		*procs += 1;
		*total_pages_touched += pages_touched;
	}

	if (opt_flags & OPT_VERBOSE) {
		printf("PID:%5d, %12zu pages, %12zu pages touched\r", pid, pages, *total_pages_touched);
		fflush(stdout);
	}
	
	(void)fclose(fpmap);
	(void)close(fdmem);

	return 0;
}

/*
 *  pagein_all_procs()
 *	attempt to page in all processes
 */
static int pagein_all_procs(
	const int64_t swapfree_begin,	
	int32_t *const procs,
	int32_t *const total_procs,
	int64_t *const total_pages_touched)
{
	DIR *dp;
	struct dirent *d;

	*procs = 0;

	dp = opendir("/proc");
	if (!dp)
		return -1;

	while ((d = readdir(dp)) != NULL) {
		pid_t pid;

		if (isdigit(d->d_name[0]) &&
                    sscanf(d->d_name, "%d", &pid) == 1) {
			*total_procs += 1;
			pagein_proc(pid, swapfree_begin, procs, total_pages_touched);
		}
	}

	(void)closedir(dp);

	return 0;
}

int main(int argc, char **argv)
{
	int64_t memfree_begin, memfree_end;
	int64_t swapfree_begin, swapfree_end;
	int64_t total_pages_touched = 0ULL;
	int32_t procs, total_procs = 0;
	struct rusage usage;
	pid_t pid = -1;

	for (;;) {
		int c = getopt(argc, argv, "adhp:v");
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
				fprintf(stderr, "bad pid: %d\n", pid);
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
		fprintf(stderr, "must not use -a and -p options together\n");
		exit(EXIT_FAILURE);
	}
	if ((opt_flags & (OPT_ALL | OPT_BY_PID)) == 0) {
		fprintf(stderr, "must use one of -a or -p, use -h for more details\n");
		exit(EXIT_FAILURE);
	}

	get_memstats(&memfree_begin, &swapfree_begin);
	if (opt_flags & OPT_ALL)
		pagein_all_procs(swapfree_begin, &procs, &total_procs, &total_pages_touched);

	if (opt_flags & OPT_BY_PID) {
		int ret;

		ret = pagein_proc(pid, swapfree_begin, &procs, &total_pages_touched);
		if (ret < 0) {
			fprintf(stderr, "cannot page in PID %d errno = %d (%s)\n",
				pid, -ret, strerror(-ret));
			exit(EXIT_FAILURE);
		}
	}

	get_memstats(&memfree_end, &swapfree_end);
	if (opt_flags & OPT_VERBOSE)
		printf("%-60.60s\r", "");

	if (opt_flags & OPT_ALL)
		printf("Processes Touched:    %" PRIu32 " (out of %" PRIu32 ")\n", procs, total_procs);
	printf("Pages Touched:        %" PRIu64 "\n", total_pages_touched);
	printf("Free Memory decrease: %" PRId64 "K (%" PRId64 " pages)\n",
		(memfree_begin - memfree_end),
		1024 * (memfree_begin - memfree_end) / (int64_t)get_pagesize());
	printf("Swap Memory decrease: %" PRId64 "K (%" PRId64 " pages)\n",
		(swapfree_begin - swapfree_end),
		1024 * (swapfree_begin - swapfree_end) / (int64_t)get_pagesize());
	if (getrusage(RUSAGE_SELF, &usage) == 0) {
		printf("Page Faults Major:    %lu\n", usage.ru_majflt);
		printf("Page Faults Minor:    %lu\n", usage.ru_minflt);
		printf("Swaps:                %lu\n", usage.ru_nswap);
	}

	return EXIT_SUCCESS;
}
