/*
 * TEST RUNNER: nvram_get_current_password_test
 *
 * The runner owns the password buffer in a slab and POISONS the tail behind the 256 bytes (the size of security.u.key.key that the caller passes)
 * during the call; the log slot tail [HWR_LOG_USE, HWR_LOG_SZ) is poisoned too.  The buffer is preset to zeros / 0xA5 / "old".  Rows flagged
 * `forked` crash the unfixed function (NULL l_password): they run in a child so the ASan report is visible but the run continues; the child
 * also checks the result.  Checks: return value of the last call, that the nvram key asked for is "bpi_wifi_password", the password (expected
 * string; untouched buffer on a failure) and that nothing behind the password changed.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "hwr_ncp.h"
#include <sanitizer/asan_interface.h>

#define PW_CAP 256
static unsigned char hwr_pw_slab[640];
static unsigned char before[PW_CAP];
static char why[200];

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_pw_slab[PW_CAP], sizeof(hwr_pw_slab) - PW_CAP);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static int check_result(const hwr_ncp_case_t *t, int ret)
{
	if (ret != t->expected_ret) { snprintf(why, sizeof(why), "returned %d, expected %d%s", ret, t->expected_ret, ret == 0 ? " (success reported)" : ""); return 0; }
	if (t->null_pw) return 1;
	if (hwr_ncp_rec.calls && strcmp(hwr_ncp_rec.key, "bpi_wifi_password")) { snprintf(why, sizeof(why), "nvram key '%s'", hwr_ncp_rec.key); return 0; }
	if (t->expected_pw == NULL) {
		if (memcmp(hwr_pw_slab, before, PW_CAP)) { snprintf(why, sizeof(why), "buffer modified although the read failed"); return 0; }
	} else {
		if (strcmp((char *)hwr_pw_slab, t->expected_pw)) { snprintf(why, sizeof(why), "password '%.20s'(%zu chars), expected '%.20s'", (char *)hwr_pw_slab, strlen((char *)hwr_pw_slab), t->expected_pw); return 0; }
	}
	return 1;
}

static int run_case(const hwr_ncp_case_t *t)
{
	char *pw;
	int ret = 0;

	why[0] = 0;
	memset(hwr_log_buf, 0, HWR_LOG_USE);
	memset(&hwr_ncp_rec, 0, sizeof(hwr_ncp_rec));
	hwr_ncp_rec.ret[0] = t->nvram_ret; hwr_ncp_rec.val[0] = t->nvram_val ? t->nvram_val : "";
	hwr_ncp_rec.ret[1] = t->nvram_ret2; hwr_ncp_rec.val[1] = t->nvram_val2 ? t->nvram_val2 : "";
	memset(hwr_pw_slab, 0xA5, sizeof(hwr_pw_slab));
	if (t->prefill == 0) memset(hwr_pw_slab, 0, PW_CAP);
	else if (t->prefill == 2) { memset(hwr_pw_slab, 0, PW_CAP); memcpy(hwr_pw_slab, "old", 4); }
	else memset(hwr_pw_slab, 0xA5, PW_CAP);
	memcpy(before, hwr_pw_slab, PW_CAP);
	pw = t->null_pw ? NULL : (char *)hwr_pw_slab;

	if (t->forked) {
		int st; pid_t pid;
		fflush(stdout);
		poison(1);
		pid = fork();
		if (pid == 0) { for (int i = 0; i < t->calls; i++) ret = hwr_nvram_get_current_password(pw, t->vap_index); poison(0); _exit(check_result(t, ret) ? 0 : 2); }
		waitpid(pid, &st, 0);
		poison(0);
		if (!WIFEXITED(st)) { snprintf(why, sizeof(why), "child died"); return 0; }
		if (WEXITSTATUS(st) == 1) { snprintf(why, sizeof(why), "child aborted by AddressSanitizer (NULL l_password written)"); return 0; }
		if (WEXITSTATUS(st) != 0) { snprintf(why, sizeof(why), "child did not return the expected result"); return 0; }
		return 1;
	}
	poison(1);
	for (int i = 0; i < t->calls; i++) ret = hwr_nvram_get_current_password(pw, t->vap_index);
	poison(0);
	return check_result(t, ret);
}

extern "C" void run_all_tests_nvram_get_current_password(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; nvram_get_current_password_suite[i].test_name != NULL; i++) {
		hwr_ncp_case_t *test = &nvram_get_current_password_suite[i];

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
	printf("\nnvram_get_current_password: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
