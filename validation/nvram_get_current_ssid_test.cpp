/*
 * TEST RUNNER: nvram_get_current_ssid_test
 *
 * The runner owns the ssid buffer in a slab and POISONS the tail behind the 16 bytes (BPI_LEN_16) the function may write (bytes [16, end), the
 * caller's buffer is 32 bytes) during the call; the log slot tail [HWR_LOG_USE, HWR_LOG_SZ) is poisoned too.  The buffer is preset to zeros /
 * 0xA5.  Rows flagged `forked` crash the unfixed function (NULL l_ssid): they run in a child so the ASan report is visible but the run continues;
 * the child also checks the result.  Checks: return value, the SSID string (the MLO build always expects "BPI-RDKB-MLO-AP"), the buffer
 * untouched on -1, byte 16 and on (must keep the preset value), the previous log text.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "hwr_ncs.h"
#include <sanitizer/asan_interface.h>

#define WRITE_MAX 16
static unsigned char hwr_ssid_slab[64];
static unsigned char before[64];
static char why[200];

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_ssid_slab[WRITE_MAX], sizeof(hwr_ssid_slab) - WRITE_MAX);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static int check_result(const hwr_ncs_case_t *t, int ret)
{
	int exp_ret = t->expected_ret;
	const char *exp_ssid = t->expected_ssid;

#ifdef CONFIG_GENERIC_MLO
	if (!t->null_ssid) { exp_ret = 0; exp_ssid = "BPI-RDKB-MLO-AP"; }
#endif
	if (ret != exp_ret) { snprintf(why, sizeof(why), "returned %d, expected %d%s", ret, exp_ret, ret == 0 ? " (success reported)" : ""); return 0; }
	if (t->null_ssid) return 1;
	if (exp_ssid == NULL) {
		if (memcmp(hwr_ssid_slab, before, WRITE_MAX)) { snprintf(why, sizeof(why), "buffer modified although the name does not fit"); return 0; }
	} else if (strcmp((char *)hwr_ssid_slab, exp_ssid)) { snprintf(why, sizeof(why), "ssid '%.20s', expected '%s'", (char *)hwr_ssid_slab, exp_ssid); return 0; }
	for (int i = 0; i < t->log_prefill; i++) if (hwr_log_buf[i] != 'x') { snprintf(why, sizeof(why), "previous log byte %d modified", i); return 0; }
	return 1;
}

static int run_case(const hwr_ncs_case_t *t)
{
	char *ssid;
	int ret = 0;

	why[0] = 0;
	memset(hwr_log_buf, 0, HWR_LOG_SZ);
	memset(hwr_log_buf, 'x', t->log_prefill);
	memset(hwr_ssid_slab, 0xA5, sizeof(hwr_ssid_slab));
	if (t->prefill == 0) memset(hwr_ssid_slab, 0, WRITE_MAX);
	memcpy(before, hwr_ssid_slab, sizeof(before));
	ssid = t->null_ssid ? NULL : (char *)hwr_ssid_slab;

	if (t->forked) {
		int st; pid_t pid;
		fflush(stdout);
		poison(1);
		pid = fork();
		if (pid == 0) { for (int i = 0; i < t->calls; i++) ret = hwr_nvram_get_current_ssid(ssid, t->vap_index); poison(0); _exit(check_result(t, ret) ? 0 : 2); }
		waitpid(pid, &st, 0);
		poison(0);
		if (!WIFEXITED(st)) { snprintf(why, sizeof(why), "child died"); return 0; }
		if (WEXITSTATUS(st) == 1) { snprintf(why, sizeof(why), "child aborted by AddressSanitizer (NULL l_ssid written)"); return 0; }
		if (WEXITSTATUS(st) != 0) { snprintf(why, sizeof(why), "child did not return the expected result"); return 0; }
		return 1;
	}
	poison(1);
	for (int i = 0; i < t->calls; i++) ret = hwr_nvram_get_current_ssid(ssid, t->vap_index);
	poison(0);
	if (memcmp(&hwr_ssid_slab[WRITE_MAX], &before[WRITE_MAX], sizeof(hwr_ssid_slab) - WRITE_MAX)) { snprintf(why, sizeof(why), "bytes behind the 16-byte name modified"); return 0; }
	return check_result(t, ret);
}

extern "C" void run_all_tests_nvram_get_current_ssid(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; nvram_get_current_ssid_suite[i].test_name != NULL; i++) {
		hwr_ncs_case_t *test = &nvram_get_current_ssid_suite[i];

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
	printf("\nnvram_get_current_ssid: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
