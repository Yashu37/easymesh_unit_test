/*
 * TEST RUNNER: wifi_nvram_defaultRead_test
 *
 * The runner writes the case's file content to a temporary directory (the function's shell command / fopen is redirected
 * there, see the handler), owns the key and the caller's output buffer in slabs and POISONS their tails during the call:
 *   hwr_key_slab : [strlen(key) + 1, end)                the key string
 *   hwr_out_slab : [cap, end)                            everything behind the caller's output buffer (cap bytes)
 *   hwr_log_buf  : [HWR_LOG_USE, HWR_LOG_SZ)
 * The output buffer is preset to 0xA5 so "written" / "untouched" is visible.  After every call it checks the result, the
 * output (value + NUL, nothing else touched; untouched on a failure), and whether the marker file exists - the key
 * "...touch <marker>..." must not run a command.  Rows flagged `forked` crash the unfixed function (NULL out, a value
 * longer than the buffer): they run in a child so the ASan report is visible but the run continues; the child also
 * checks the result.  The function is NOT modified.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "hwr_nvr.h"
#include <sanitizer/asan_interface.h>

static unsigned char hwr_key_slab[256];
static unsigned char hwr_out_slab[512];
static size_t key_len, cap_now;
static char tmpdir[128], marker[160];

static void poison_all(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_key_slab[key_len + 1], sizeof(hwr_key_slab) - (key_len + 1));
	fn(&hwr_out_slab[cap_now], sizeof(hwr_out_slab) - cap_now);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static char why[220];

static void build(const hwr_nvr_case_t *t)
{
	memset(hwr_log_buf, 0, HWR_LOG_USE);
	memset(hwr_key_slab, 0, sizeof(hwr_key_slab));
	memset(hwr_out_slab, 0xA5, sizeof(hwr_out_slab));
	cap_now = t->cap;
	key_len = 0;
	if (t->key) {                                           /* "%M" -> marker path */
		const char *m = strstr(t->key, "%M");
		if (m) snprintf((char *)hwr_key_slab, sizeof(hwr_key_slab), "%.*s%s%s", (int)(m - t->key), t->key, marker, m + 2);
		else snprintf((char *)hwr_key_slab, sizeof(hwr_key_slab), "%s", t->key);
		key_len = strlen((char *)hwr_key_slab);
	}
	unlink(hwr_nvr_path); unlink(marker);
	if (t->file) { FILE *f = fopen(hwr_nvr_path, "w"); fputs(t->file, f); fclose(f); }
}

static int check_result(const hwr_nvr_case_t *t, int ret)
{
	if (t->marker_forbidden && access(marker, F_OK) == 0) { snprintf(why, sizeof(why), "an injected command ran (marker file created)"); return 0; }
	if (ret != t->expected_ret) {
		snprintf(why, sizeof(why), "returned %d, expected %d%s", ret, t->expected_ret, (ret == 0 && t->expected_ret != 0) ? " (a value was returned)" : "");
		return 0;
	}
	if (!t->null_out) {
		if (t->expected_out == NULL) {
			for (size_t k = 0; k < t->cap; k++) if (hwr_out_slab[k] != 0xA5) { snprintf(why, sizeof(why), "output byte %zu written although the call failed", k); return 0; }
		} else {
			size_t want = strlen(t->expected_out);
			if (strcmp((char *)hwr_out_slab, t->expected_out)) { snprintf(why, sizeof(why), "output '%.40s', expected '%.40s'", (char *)hwr_out_slab, t->expected_out); return 0; }
			for (size_t k = want + 1; k < t->cap; k++) if (hwr_out_slab[k] != 0xA5) { snprintf(why, sizeof(why), "byte %zu behind the value modified", k); return 0; }
		}
	}
	return 1;
}

static int run_case(const hwr_nvr_case_t *t)
{
	char *key, *out;
	int ret;

	why[0] = 0;
	build(t);
	key = t->key ? (char *)hwr_key_slab : NULL;
	out = t->null_out ? NULL : (char *)hwr_out_slab;

	if (t->forked) {                                         /* ASan report visible, run continues */
		int st; pid_t pid;
		fflush(stdout);
		poison_all(1);
		pid = fork();
		if (pid == 0) { ret = hwr_nvr_call(key, out, t->cap); poison_all(0); _exit(check_result(t, ret) ? 0 : 2); }
		waitpid(pid, &st, 0);
		poison_all(0);
		if (!WIFEXITED(st)) { snprintf(why, sizeof(why), "child died"); return 0; }
		if (WEXITSTATUS(st) == 1) { snprintf(why, sizeof(why), "child aborted by AddressSanitizer (%s)", t->null_out ? "NULL out written" : "value longer than the caller's buffer copied into it"); return 0; }
		if (WEXITSTATUS(st) != 0) { snprintf(why, sizeof(why), "child did not return the expected result"); return 0; }
		return 1;
	}

	poison_all(1);
	ret = hwr_nvr_call(key, out, t->cap);
	poison_all(0);
	return check_result(t, ret);
}

extern "C" void run_all_tests_wifi_nvram_defaultRead(void)
{
	int pass = 0, fail = 0;

	snprintf(tmpdir, sizeof(tmpdir), "/tmp/hwr_nvr_XXXXXX");
	if (!mkdtemp(tmpdir)) { printf("mkdtemp failed\n"); return; }
	snprintf(hwr_nvr_path, sizeof(hwr_nvr_path), "%s/wifi_defaults.txt", tmpdir);
	snprintf(marker, sizeof(marker), "%s/pwned", tmpdir);

	for (int i = 0; wifi_nvram_defaultRead_suite[i].test_name != NULL; i++) {
		hwr_nvr_case_t *test = &wifi_nvram_defaultRead_suite[i];

		printf("--- Running Test: %s ---\n", test->test_name);

		int ret = run_case(test);

		if (ret == 1) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=1, got=%d) %s =====\n", test->test_name, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	unlink(hwr_nvr_path); unlink(marker); rmdir(tmpdir);
	printf("\nwifi_nvram_defaultRead: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
