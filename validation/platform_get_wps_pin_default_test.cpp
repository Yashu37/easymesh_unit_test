/*
 * TEST RUNNER: platform_get_wps_pin_default_test
 *
 * The runner owns the pin buffer in a slab and POISONS the tail behind the 128 bytes the callers pass during the call:
 *   hwr_pin_slab : [128, end)   the buffer is preset to zeros (what the callers do) or 0xA5 (uninitialised, no NUL)
 *   hwr_log_buf  : [HWR_LOG_USE, HWR_LOG_SZ)
 * Rows flagged `forked` crash the unfixed function (NULL pin, a 128-character value that needs 129 bytes): they run in a child so the ASan
 * report is visible but the run continues; the child also checks the result.  Checks: return value, that the key asked from nvram is
 * "wps_pin", the pin (expected string; untouched buffer on -1), and the bytes behind the pin.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "hwr_pwp.h"
#include <sanitizer/asan_interface.h>

#define PIN_CAP 128
static unsigned char hwr_pin_slab[512];
static char why[200];

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_pin_slab[PIN_CAP], sizeof(hwr_pin_slab) - PIN_CAP);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static int check_result(const hwr_pwp_case_t *t, int ret)
{
	if (ret != t->expected_ret) { snprintf(why, sizeof(why), "returned %d, expected %d%s", ret, t->expected_ret, ret == 0 ? " (success reported)" : ""); return 0; }
	if (t->null_pin) return 1;
	if (t->expected_pin == NULL) {
		unsigned char fill = t->prefill == 1 ? 0xA5 : 0;
		for (size_t k = 0; k < PIN_CAP; k++) if (hwr_pin_slab[k] != fill) { snprintf(why, sizeof(why), "pin byte %zu written although the call failed", k); return 0; }
	} else {
		if (strcmp((char *)hwr_pin_slab, t->expected_pin)) { snprintf(why, sizeof(why), "pin '%.20s', expected '%.20s'", (char *)hwr_pin_slab, t->expected_pin); return 0; }
	}
	if (hwr_pwp_rec.calls == 0 && !t->null_pin) { snprintf(why, sizeof(why), "nvram not asked"); return 0; }
	if (hwr_pwp_rec.calls && strcmp(hwr_pwp_rec.key, "wps_pin")) { snprintf(why, sizeof(why), "nvram key '%s'", hwr_pwp_rec.key); return 0; }
	return 1;
}

static int run_case(const hwr_pwp_case_t *t)
{
	char *pin;
	int ret;

	why[0] = 0;
	memset(hwr_log_buf, 0, HWR_LOG_USE);
	memset(&hwr_pwp_rec, 0, sizeof(hwr_pwp_rec));
	hwr_pwp_rec.nvram_ret = t->nvram_ret; hwr_pwp_rec.nvram_val = t->nvram_val ? t->nvram_val : "";
	memset(hwr_pin_slab, 0xA5, sizeof(hwr_pin_slab));
	if (t->prefill == 0) memset(hwr_pin_slab, 0, PIN_CAP);
	pin = t->null_pin ? NULL : (char *)hwr_pin_slab;

	if (t->forked) {
		int st; pid_t pid;
		fflush(stdout);
		poison(1);
		pid = fork();
		if (pid == 0) { ret = hwr_platform_get_wps_pin_default(pin); poison(0); _exit(check_result(t, ret) ? 0 : 2); }
		waitpid(pid, &st, 0);
		poison(0);
		if (!WIFEXITED(st)) { snprintf(why, sizeof(why), "child died"); return 0; }
		if (WEXITSTATUS(st) == 1) { snprintf(why, sizeof(why), "child aborted by AddressSanitizer (%s)", t->null_pin ? "NULL pin written" : "128-char value copied into 128 bytes"); return 0; }
		if (WEXITSTATUS(st) != 0) { snprintf(why, sizeof(why), "child did not return the expected result"); return 0; }
		return 1;
	}
	poison(1);
	ret = hwr_platform_get_wps_pin_default(pin);
	poison(0);
	return check_result(t, ret);
}

extern "C" void run_all_tests_platform_get_wps_pin_default(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; platform_get_wps_pin_default_suite[i].test_name != NULL; i++) {
		hwr_pwp_case_t *test = &platform_get_wps_pin_default_suite[i];

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
	printf("\nplatform_get_wps_pin_default: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
