/*
 * UNIT TEST (input constructor): construct_dpp_dummy
 *
 * dpp_dummy() has no parameters, no arrays and no dynamic memory; its only
 * observable behaviour is printf() to stdout.  The "inputs" are therefore
 * the state of stdout and the calling context: where fd 1 points (file /
 * pipe / /dev/null / /dev/full / closed), the stdio buffering mode, the
 * call count, thread/fork context and interleaving with other output.
 * Each suite entry is a scenario that sets that state up, calls the
 * handler, and returns 1 when the observed result is what is expected.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <locale.h>
#include <sys/wait.h>
#include <string>
#include "common.h"

void dpp_dummy();

char dpp_cap_buf[DPP_CAP_SZ];

static const char *EXP = "dummy stub for dpp hal";

/* ---- stdout capture into a temp file ---- */
static int saved_fd = -1, cap_fd = -1;
static char cap_path[] = "/tmp/dpp_dummy_cap_XXXXXX";

static void cap_begin(void)
{
	fflush(stdout);
	saved_fd = dup(1);
	cap_fd = mkstemp(cap_path);
	dup2(cap_fd, 1);
}

static std::string cap_end(void)
{
	std::string s;
	char buf[4096];
	ssize_t n;

	fflush(stdout);
	dup2(saved_fd, 1);
	close(saved_fd);
	lseek(cap_fd, 0, SEEK_SET);
	while ((n = read(cap_fd, buf, sizeof(buf))) > 0)
		s.append(buf, n);
	close(cap_fd);
	unlink(cap_path);
	strcpy(cap_path, "/tmp/dpp_dummy_cap_XXXXXX");
	return s;
}

static std::string rep(int n)
{
	std::string s;
	for (int i = 0; i < n; i++)
		s += EXP;
	return s;
}

static std::string run_calls(int n)
{
	cap_begin();
	for (int i = 0; i < n; i++)
		dpp_dummy();
	return cap_end();
}

static int run_n(int n)
{
	return run_calls(n) == rep(n);
}

static int to_dest(const char *path, int flags, int *err_out)
{
	int sv, fd;

	fflush(stdout);
	sv = dup(1);
	fd = open(path, flags);
	dup2(fd, 1);
	dpp_dummy();
	fflush(stdout);
	if (err_out) {
		*err_out = ferror(stdout);
		clearerr(stdout);
	}
	dup2(sv, 1);
	close(sv);
	close(fd);
	return 1;
}

static void *thr(void *) { for (int i = 0; i < 100; i++) dpp_dummy(); return NULL; }

static int mode_test(int mode, size_t sz)
{
	static char big[1 << 20];

	fflush(stdout);
	setvbuf(stdout, mode == _IOFBF ? big : NULL, mode, sz);
	int ok = run_n(3);
	fflush(stdout);
	setvbuf(stdout, NULL, _IONBF, 0);
	return ok;
}

dpp_dummy_test_case_t dpp_dummy_suite[] = {
	/* ---- exact output ---- */
	{ "output_exact_single_call",        [](void)->int { return run_calls(1) == EXP; }, 1 },
	{ "output_length",                   [](void)->int { return run_calls(1).size() == strlen(EXP); }, 1 },
	{ "output_no_trailing_newline",      [](void)->int { std::string s = run_calls(1); return !s.empty() && s.back() != '\n'; }, 1 },
	{ "output_no_embedded_nul",          [](void)->int { return run_calls(1).find('\0') == std::string::npos; }, 1 },
	{ "output_starts_with_dummy",        [](void)->int { return run_calls(1).rfind("dummy", 0) == 0; }, 1 },
	{ "output_ends_with_hal",            [](void)->int { std::string s = run_calls(1); return s.size() >= 3 && s.compare(s.size() - 3, 3, "hal") == 0; }, 1 },

	/* ---- call counts ---- */
	{ "repeat_0_calls",                  [](void)->int { return run_n(0); }, 1 },
	{ "repeat_2_calls",                  [](void)->int { return run_n(2); }, 1 },
	{ "repeat_3_calls",                  [](void)->int { return run_n(3); }, 1 },
	{ "repeat_5_calls",                  [](void)->int { return run_n(5); }, 1 },
	{ "repeat_10_calls",                 [](void)->int { return run_n(10); }, 1 },
	{ "repeat_50_calls",                 [](void)->int { return run_n(50); }, 1 },
	{ "repeat_100_calls",                [](void)->int { return run_n(100); }, 1 },
	{ "repeat_1000_calls",               [](void)->int { return run_n(1000); }, 1 },
	{ "repeat_5000_calls",               [](void)->int { return run_n(5000); }, 1 },

	/* ---- stdio buffering modes ---- */
	{ "unbuffered_stdout",               [](void)->int { return mode_test(_IONBF, 0); }, 1 },
	{ "line_buffered_stdout",            [](void)->int { return mode_test(_IOLBF, 0); }, 1 },
	{ "fully_buffered_1MiB_buffer",      [](void)->int { return mode_test(_IOFBF, 1 << 20); }, 1 },

	/* ---- destination variants ---- */
	{ "dest_dev_null_no_crash",          [](void)->int { return to_dest("/dev/null", O_WRONLY, NULL); }, 1 },
	{ "dest_dev_full_sets_stream_error", [](void)->int { int e = 0; to_dest("/dev/full", O_WRONLY, &e); return e != 0; }, 1 },
	{ "dest_closed_fd_no_crash",         [](void)->int {
		fflush(stdout); int sv = dup(1); close(1);
		dpp_dummy(); fflush(stdout); clearerr(stdout);
		dup2(sv, 1); close(sv); return 1; }, 1 },
	{ "dest_pipe",                       [](void)->int {
		int p[2]; char b[128] = {0};
		pipe(p); fflush(stdout); int sv = dup(1); dup2(p[1], 1);
		dpp_dummy(); fflush(stdout); dup2(sv, 1); close(sv); close(p[1]);
		ssize_t n = read(p[0], b, sizeof(b) - 1); close(p[0]);
		return n == (ssize_t)strlen(EXP) && !strcmp(b, EXP); }, 1 },
	{ "dest_append_file_after_PRE",      [](void)->int {
		char path[] = "/tmp/dpp_dummy_app_XXXXXX"; char b[128] = {0};
		int fd = mkstemp(path); write(fd, "PRE", 3); close(fd);
		fd = open(path, O_WRONLY | O_APPEND);
		fflush(stdout); int sv = dup(1); dup2(fd, 1);
		dpp_dummy(); fflush(stdout); dup2(sv, 1); close(sv); close(fd);
		FILE *f = fopen(path, "r"); fread(b, 1, sizeof(b) - 1, f); fclose(f); unlink(path);
		return std::string(b) == std::string("PRE") + EXP; }, 1 },

	/* ---- interleaving with other output ---- */
	{ "interleave_A_dummy_B",            [](void)->int { cap_begin(); printf("A"); dpp_dummy(); printf("B");
		return cap_end() == std::string("A") + EXP + "B"; }, 1 },
	{ "interleave_newline_between",      [](void)->int { cap_begin(); dpp_dummy(); printf("\n"); dpp_dummy();
		return cap_end() == std::string(EXP) + "\n" + EXP; }, 1 },
	{ "interleave_stdio_mix",            [](void)->int { cap_begin(); fputs("x", stdout); dpp_dummy(); putchar('y'); dpp_dummy();
		return cap_end() == std::string("x") + EXP + "y" + EXP; }, 1 },

	/* ---- side effects ---- */
	{ "errno_unchanged_on_success",      [](void)->int { errno = 0; run_calls(1); return errno == 0 || errno == ENOTTY || errno == ESPIPE; }, 1 },
	{ "no_stream_error_on_good_stdout",  [](void)->int { cap_begin(); dpp_dummy(); int er = ferror(stdout); cap_end(); return er == 0; }, 1 },
	{ "heap_canary_intact",              [](void)->int {
		unsigned char *c = (unsigned char *)malloc(64); int ok = 1;
		memset(c, 0xA5, 64); run_calls(10);
		for (int i = 0; i < 64; i++) if (c[i] != 0xA5) ok = 0;
		free(c); return ok; }, 1 },
	{ "locale_C_output_same",            [](void)->int { setlocale(LC_ALL, "C"); return run_calls(1) == EXP; }, 1 },
	{ "deterministic_20_separate_runs",  [](void)->int { for (int i = 0; i < 20; i++) if (run_calls(1) != EXP) return 0; return 1; }, 1 },

	/* ---- calling context ---- */
	{ "call_via_function_pointer",       [](void)->int { void (*fp)() = dpp_dummy; cap_begin(); fp(); return cap_end() == EXP; }, 1 },
	{ "call_from_thread_100x",           [](void)->int { pthread_t t; cap_begin(); pthread_create(&t, NULL, thr, NULL); pthread_join(t, NULL);
		return cap_end() == rep(100); }, 1 },
	{ "call_from_4_threads_no_tearing",  [](void)->int { pthread_t ts[4]; cap_begin();
		for (int i = 0; i < 4; i++) pthread_create(&ts[i], NULL, thr, NULL);
		for (int i = 0; i < 4; i++) pthread_join(ts[i], NULL);
		return cap_end() == rep(400); }, 1 },
	{ "call_in_fork_child",              [](void)->int {
		int p[2], st; char b[128] = {0};
		pipe(p); fflush(stdout);
		pid_t pid = fork();
		if (pid == 0) { dup2(p[1], 1); close(p[0]); dpp_dummy(); fflush(stdout); _exit(0); }
		close(p[1]); read(p[0], b, sizeof(b) - 1); close(p[0]); waitpid(pid, &st, 0);
		return !strcmp(b, EXP) && WIFEXITED(st) && WEXITSTATUS(st) == 0; }, 1 },
	{ NULL, NULL, 0 }
};

static const dpp_dummy_test_case_t *cur_tc;

void construct_dpp_dummy_input(const dpp_dummy_test_case_t *tc)
{
	cur_tc = tc;
	memset(dpp_cap_buf, 0, DPP_CAP_SZ);
}

int dpp_dummy_run_current(void)
{
	return cur_tc->scenario();
}
