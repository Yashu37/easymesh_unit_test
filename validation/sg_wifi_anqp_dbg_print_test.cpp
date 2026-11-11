/*
 * TEST RUNNER: sg_wifi_anqp_dbg_print_test
 *
 * test_sg_wifi_anqp_dbg_print() POISONS what the function must not touch, calls the handler and unpoisons: the world's unrelated members, the guard slab and the log slot tail
 * [HWR_LOG_USE, HWR_LOG_SZ).  The format ("%s") and the message are exact heap blocks.  The 4096-byte local buffer lives on the stack inside the function, so its overflow is reported by ASan itself.  The
 * output goes to a runner temp file; run_all_tests compares it with a reference model of the CORRECT behaviour (see the construct file), including the model of the function-static FILE * (opened once, only
 * while access is OK): access / open / time calls (not prescribed for a NULL format), exact bytes appended (truncated to 4095 characters), nothing appended when the flag file is missing or the open fails, guard slab unchanged.
 * Rows with last = 1 break the original: they run LAST.
 */
#include <stdio.h>
#include <string>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include "hwr_wdp.h"
#include <sanitizer/asan_interface.h>

static char why[300];
static char *fmt, *msg;
static int model_open;          /* model of the function-static FILE * (stays open once opened) */
static off_t read_off;

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(hwr_wdp_world.unrelated, sizeof(hwr_wdp_world.unrelated));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_anqp_dbg_print(const hwr_wdp_case_t *t)
{
	poison(1);
	if (t->msg_len < 0) hwr_sg_wifi_anqp_dbg_print(t->level, NULL, msg);
	else hwr_sg_wifi_anqp_dbg_print(t->level, fmt, msg);
	poison(0);
}

static int check(const hwr_wdp_case_t *t)
{
	const hwr_wdp_world_t *w = &hwr_wdp_world;
	int want_open_call = 0, want_write = 0;
	std::string expect;
	struct stat st; char *got = NULL; ssize_t n = 0; int ok = 1;

	if (t->access_ok && t->msg_len >= 0) {
		if (!model_open) { want_open_call = 1; if (t->fopen_ok) { model_open = 1; want_write = 1; } }
		else want_write = 1;
	} else if (t->access_ok) {
		/* NULL format: the correct function writes nothing (the open is not prescribed) */
		want_open_call = -1;
	}
	if (want_write) {
		std::string m(msg);
		expect = std::string(HWR_WDP_TS) + " " + m;
		if (expect.size() > 4095) expect.resize(4095);
	}
	if (t->msg_len >= 0 && w->access_calls != 1) { snprintf(why, sizeof(why), "access ran %d times, expected 1", w->access_calls); return 0; }
	if (want_open_call >= 0 && w->fopen_calls != want_open_call) { snprintf(why, sizeof(why), "fopen ran %d times, expected %d", w->fopen_calls, want_open_call); return 0; }
	fflush(w->file);
	fstat(fileno(w->file), &st);
	n = st.st_size - read_off;
	if (n < 0) n = 0;
	got = (char *)malloc(n + 1);
	if (n) { ssize_t r = pread(fileno(w->file), got, n, read_off); (void)r; }
	got[n] = 0;
	read_off = st.st_size;
	if ((size_t)n != expect.size() || memcmp(got, expect.data(), expect.size()) != 0) {
		snprintf(why, sizeof(why), "appended %zd bytes, expected %zu (bytes %s)", n, expect.size(), (size_t)n == expect.size() ? "differ" : "n/a");
		ok = 0;
	}
	free(got);
	if (!ok) return 0;
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

static void setup(const hwr_wdp_case_t *t)
{
	hwr_wdp_world_t *w = &hwr_wdp_world;
	FILE *f = w->file;

	memset(w, 0, sizeof(*w));
	w->file = f;
	w->access_ok = t->access_ok; w->fopen_ok = t->fopen_ok;
	fmt = (char *)malloc(3); strcpy(fmt, "%s");
	{
		int len = t->msg_len < 0 ? 5 : t->msg_len;
		msg = (char *)malloc(len + 1);
		for (int i = 0; i < len; i++) msg[i] = 'a' + (i % 26);
		msg[len] = 0;
	}
}

extern "C" void run_all_tests_sg_wifi_anqp_dbg_print(void)
{
	int pass = 0, fail = 0;

	hwr_wdp_world.file = tmpfile();
	model_open = 0; read_off = 0;
	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_anqp_dbg_print_suite[i].test_name != NULL; i++) {
			hwr_wdp_case_t *test = &sg_wifi_anqp_dbg_print_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_anqp_dbg_print(test);

			int ok = check(test);
			free(fmt); free(msg); fmt = msg = NULL;
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_anqp_dbg_print: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
