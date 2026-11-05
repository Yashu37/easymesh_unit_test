/*
 * TEST RUNNER: json_parse_backhaul_keypassphrase_test
 *
 * Writes the case's file to a temporary directory (the function's fopen is redirected there, see the handler), owns the
 * caller's output buffer in a slab and POISONS its tail during the call:
 *   hwr_out_slab : [MAX_KEYPASSPHRASE_LEN (129), end)   everything behind the 129-byte buffer the function may write
 *   hwr_log_buf  : [HWR_LOG_USE, HWR_LOG_SZ)
 * out is preset to 0xA5 so "written" / "untouched" is visible.  After the call it checks the result and the output (value
 * + NUL and nothing else touched on success; untouched on failure).  Rows flagged `forked` crash the unfixed function
 * (NULL out): they run in a child so the ASan report is visible but the run continues.  The function is NOT modified.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "hwr_jbk.h"
#include <sanitizer/asan_interface.h>

#define OUT_CAP 129
static unsigned char hwr_out_slab[512];
static char tmpdir[128], why[220];

static void poison_all(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_out_slab[OUT_CAP], sizeof(hwr_out_slab) - OUT_CAP);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* replace "%V" by n 'k' */
static char *expand(const char *s, int n)
{
	const char *m = strstr(s, "%V");
	size_t head, tail;
	char *r;

	if (!m) return strdup(s);
	head = m - s; tail = strlen(m + 2);
	r = (char *)malloc(head + n + tail + 1);
	memcpy(r, s, head); memset(r + head, 'k', n); memcpy(r + head + n, m + 2, tail + 1);
	return r;
}

static int check_result(const hwr_jbk_case_t *t, int ret, const char *want)
{
	if (ret != t->expected_ret) { snprintf(why, sizeof(why), "returned %d, expected %d%s", ret, t->expected_ret, ret == 0 ? " (a value was returned)" : ""); return 0; }
	if (t->null_out) return 1;
	if (want == NULL) {
		for (size_t k = 0; k < OUT_CAP; k++) if (hwr_out_slab[k] != 0xA5) { snprintf(why, sizeof(why), "output byte %zu written although the call failed", k); return 0; }
	} else {
		if (strcmp((char *)hwr_out_slab, want)) { snprintf(why, sizeof(why), "output '%.40s'(%zu chars), expected %zu chars", (char *)hwr_out_slab, strlen((char *)hwr_out_slab), strlen(want)); return 0; }
		for (size_t k = strlen(want) + 1; k < OUT_CAP; k++) if (hwr_out_slab[k] != 0xA5 && hwr_out_slab[k] != 0) { snprintf(why, sizeof(why), "byte %zu behind the value modified", k); return 0; }
	}
	return 1;
}

static int run_case(const hwr_jbk_case_t *t)
{
	char *file = NULL, *want = NULL, *out;
	int ret, ok;

	why[0] = 0;
	memset(hwr_log_buf, 0, HWR_LOG_USE);
	memset(hwr_out_slab, 0xA5, sizeof(hwr_out_slab));
	unlink(hwr_jbk_path);
	if (t->file) {
		file = expand(t->file, t->long_len);
		FILE *f = fopen(hwr_jbk_path, "w"); fwrite(file, 1, strlen(file), f); fclose(f);
	}
	if (t->expected_out) want = expand(t->expected_out, t->long_len);
	out = t->null_out ? NULL : (char *)hwr_out_slab;

	if (t->forked) {
		int st; pid_t pid;
		fflush(stdout);
		poison_all(1);
		pid = fork();
		if (pid == 0) { ret = hwr_jbk_call(out); poison_all(0); _exit(check_result(t, ret, want) ? 0 : 2); }
		waitpid(pid, &st, 0);
		poison_all(0);
		free(file); free(want);
		if (!WIFEXITED(st)) { snprintf(why, sizeof(why), "child died"); return 0; }
		if (WEXITSTATUS(st) == 1) { snprintf(why, sizeof(why), "child aborted by AddressSanitizer (%s)", t->null_out ? "NULL out written" : "heap-buffer-overflow reading the parse-error text"); return 0; }
		if (WEXITSTATUS(st) != 0) { snprintf(why, sizeof(why), "child did not return the expected result"); return 0; }
		return 1;
	}
	poison_all(1);
	ret = hwr_jbk_call(out);
	poison_all(0);
	ok = check_result(t, ret, want);
	free(file); free(want);
	return ok;
}

extern "C" void run_all_tests_json_parse_backhaul_keypassphrase(void)
{
	int pass = 0, fail = 0;

	snprintf(tmpdir, sizeof(tmpdir), "/tmp/hwr_jbk_XXXXXX");
	if (!mkdtemp(tmpdir)) { printf("mkdtemp failed\n"); return; }
	snprintf(hwr_jbk_path, sizeof(hwr_jbk_path), "%s/EasymeshCfg.json", tmpdir);

	for (int i = 0; json_parse_backhaul_keypassphrase_suite[i].test_name != NULL; i++) {
		hwr_jbk_case_t *test = &json_parse_backhaul_keypassphrase_suite[i];

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
	unlink(hwr_jbk_path); rmdir(tmpdir);
	printf("\njson_parse_backhaul_keypassphrase: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
