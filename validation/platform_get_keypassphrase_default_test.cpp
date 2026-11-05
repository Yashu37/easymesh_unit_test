/*
 * TEST RUNNER: platform_get_keypassphrase_default_test
 *
 * The runner owns the password buffer in a slab and POISONS the tail behind the caller's buffer during the call:
 *   hwr_pw_slab : [cap, end)   cap = 128 (the size of the buffers wifi_db_apis.c / wifi_ctrl_webconfig.c / wifi_multidoc_webconfig.c pass) or
 *                              64 (wifi_dml_cb.c) for the prefill-3 rows; the buffer is preset to zeros, to 0xA5 (uninitialised stack
 *                              garbage, no NUL) or to "junk"
 *   hwr_log_buf : [HWR_LOG_USE, HWR_LOG_SZ)
 * Rows flagged `forked` crash the unfixed function (NULL password, strlen over an unterminated buffer, the JSON copy that writes 129
 * bytes into the 128-byte buffer): they run in a child so the ASan report is visible but the run continues; the child also checks the
 * result.  Checks: return value, the password (expected string; the bytes behind it unchanged), the number of collaborator calls (the JSON
 * source is only used for the mesh STA index, the nvram source only when needed) and, for the fallback, the error line in the log.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "hwr_pgk.h"
#include <sanitizer/asan_interface.h>

static unsigned char hwr_pw_slab[512];
static size_t cap_now;
static char why[220];

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_pw_slab[cap_now], sizeof(hwr_pw_slab) - cap_now);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static void build(const hwr_pgk_case_t *t)
{
	memset(hwr_log_buf, 0, HWR_LOG_USE);
	memset(&hwr_pgk_rec, 0, sizeof(hwr_pgk_rec));
	hwr_pgk_rec.mesh_sta_index = t->mesh_sta_index;
	hwr_pgk_rec.json_ret = t->json_ret; hwr_pgk_rec.nvram_ret = t->nvram_ret;
	hwr_pgk_rec.json_val = t->json_val ? t->json_val : ""; hwr_pgk_rec.nvram_val = t->nvram_val ? t->nvram_val : "";
	cap_now = t->prefill == 3 ? 64 : 128;
	memset(hwr_pw_slab, 0xA5, sizeof(hwr_pw_slab));
	if (t->prefill == 0 || t->prefill == 3) memset(hwr_pw_slab, 0, cap_now);
	else if (t->prefill == 2) { memset(hwr_pw_slab, 0, cap_now); memcpy(hwr_pw_slab, "junk", 5); }
	else memset(hwr_pw_slab, 0xA5, cap_now);                       /* uninitialised: no NUL inside the buffer */
}

static int check_result(const hwr_pgk_case_t *t, int ret)
{
	if (ret != t->expected_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, t->expected_ret); return 0; }
	if (t->null_pw) return 1;
	if (strcmp((char *)hwr_pw_slab, t->expected_pw)) { snprintf(why, sizeof(why), "password '%.20s'(%zu chars), expected '%.20s'", (char *)hwr_pw_slab, strlen((char *)hwr_pw_slab), t->expected_pw); return 0; }
	if (hwr_pgk_rec.json_calls != t->expected_json_calls) { snprintf(why, sizeof(why), "%d JSON source calls, expected %d", hwr_pgk_rec.json_calls, t->expected_json_calls); return 0; }
	if (hwr_pgk_rec.nvram_calls != t->expected_nvram_calls) { snprintf(why, sizeof(why), "%d nvram source calls, expected %d", hwr_pgk_rec.nvram_calls, t->expected_nvram_calls); return 0; }
	if (t->expect_fallback_log && !strstr(hwr_log_buf, "enforced alternative")) { snprintf(why, sizeof(why), "fallback error line missing in the log"); return 0; }
	return 1;
}

static int run_case(const hwr_pgk_case_t *t)
{
	char *pw;
	int ret;

	why[0] = 0;
	build(t);
	pw = t->null_pw ? NULL : (char *)hwr_pw_slab;
	if (t->forked) {
		int st; pid_t pid;
		fflush(stdout);
		poison(1);
		pid = fork();
		if (pid == 0) { ret = hwr_platform_get_keypassphrase_default(pw, t->vap_index); poison(0); _exit(check_result(t, ret) ? 0 : 2); }
		waitpid(pid, &st, 0);
		poison(0);
		if (!WIFEXITED(st)) { snprintf(why, sizeof(why), "child died"); return 0; }
		if (WEXITSTATUS(st) == 1) { snprintf(why, sizeof(why), "child aborted by AddressSanitizer"); return 0; }
		if (WEXITSTATUS(st) != 0) { snprintf(why, sizeof(why), "child did not return the expected result"); return 0; }
		return 1;
	}
	poison(1);
	ret = hwr_platform_get_keypassphrase_default(pw, t->vap_index);
	poison(0);
	return check_result(t, ret);
}

extern "C" void run_all_tests_platform_get_keypassphrase_default(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; platform_get_keypassphrase_default_suite[i].test_name != NULL; i++) {
		hwr_pgk_case_t *test = &platform_get_keypassphrase_default_suite[i];

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
	printf("\nplatform_get_keypassphrase_default: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
