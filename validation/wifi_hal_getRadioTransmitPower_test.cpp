/*
 * TEST RUNNER: wifi_hal_getRadioTransmitPower_test
 *
 * The runner owns the output ULONG in a slab, POISONS its tail and the unused log slot, calls the function,
 * UNPOISONS and checks the result:
 *   hwr_out_slab : [sizeof(ULONG), end)       hwr_log_buf : [HWR_LOG_USE, HWR_LOG_SZ)
 * The output is preset to the 0xA5 pattern, so "platform failed but the wrapper said success" and "output
 * written although the call failed" are visible.  Rows flagged `forked` crash the unfixed function (NULL output
 * written by the platform): they run in a child so the ASan report is visible but the run continues.  The
 * function is NOT modified.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "hwr_gtp.h"
#include <sanitizer/asan_interface.h>

#define PADB 64
static unsigned char hwr_out_slab[sizeof(ULONG) + PADB];

static void poison_all(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_out_slab[sizeof(ULONG)], PADB);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static char why[220];

static int check_call(const hwr_gtp_case_t *t, INT ret, int i)
{
	ULONG *out = t->null_out ? NULL : (ULONG *)hwr_out_slab;
	ULONG preset; memset(&preset, 0xA5, sizeof(preset));

	if (ret != t->expected_ret) {
		snprintf(why, sizeof(why), "call %d returned %d, expected %d%s", i, ret, t->expected_ret,
		         (ret == 0 && t->callee_ret != 0) ? " (platform failed but success reported; *output_ulong left unwritten)" : "");
		return 0;
	}
	if (!t->null_out && t->callee_ret == 0 && t->expected_ret == 0) {
		if (hwr_gtp_rec.calls != 1 || hwr_gtp_rec.radio != t->radio || hwr_gtp_rec.out != out) { snprintf(why, sizeof(why), "arguments not forwarded unchanged (%d calls)", hwr_gtp_rec.calls); return 0; }
		if (*(ULONG *)hwr_out_slab != t->power) { snprintf(why, sizeof(why), "*output_ulong = %lu, expected %lu", *(ULONG *)hwr_out_slab, t->power); return 0; }
	} else if (!t->null_out) {
		if (memcmp(hwr_out_slab, &preset, sizeof(preset))) { snprintf(why, sizeof(why), "*output_ulong modified although the call failed"); return 0; }
	}
	return 1;
}

static int run_case(const hwr_gtp_case_t *t)
{
	ULONG *out = t->null_out ? NULL : (ULONG *)hwr_out_slab;
	INT ret = 0;

	why[0] = 0;
	memset(hwr_log_buf, 0, HWR_LOG_USE);

	if (t->forked) {                                         /* SEGV report visible, run continues */
		int st; pid_t pid;
		memset(hwr_out_slab, 0xA5, sizeof(hwr_out_slab));
		hwr_gtp_configure(t->callee_ret, t->power);
		fflush(stdout);
		poison_all(1);
		pid = fork();
		if (pid == 0) { ret = hwr_wifi_hal_getRadioTransmitPower(t->radio, out); _exit(ret == t->expected_ret ? 0 : 2); }
		waitpid(pid, &st, 0);
		poison_all(0);
		if (!WIFEXITED(st)) { snprintf(why, sizeof(why), "child died (SEGV on a NULL output_ulong)"); return 0; }
		if (WEXITSTATUS(st) == 1) { snprintf(why, sizeof(why), "child aborted by AddressSanitizer (SEGV: platform wrote through a NULL output_ulong)"); return 0; }
		if (WEXITSTATUS(st) != 0) { snprintf(why, sizeof(why), "child did not return the expected result (exit %d)", WEXITSTATUS(st)); return 0; }
		return 1;
	}

	for (int i = 0; i < t->calls; i++) {
		memset(hwr_out_slab, 0xA5, sizeof(hwr_out_slab));
		hwr_gtp_configure(t->callee_ret, t->power);
		poison_all(1);
		ret = hwr_wifi_hal_getRadioTransmitPower(t->radio, out);
		poison_all(0);
		if (!check_call(t, ret, i)) return 0;
	}
	if (t->check_log && (!strstr(hwr_log_buf, "wifi_hal_getRadioTransmitPower") || !strstr(hwr_log_buf, "Enter"))) { snprintf(why, sizeof(why), "log lacks function name / Enter: '%s'", hwr_log_buf); return 0; }
	return 1;
}

extern "C" void run_all_tests_wifi_hal_getRadioTransmitPower(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; wifi_hal_getRadioTransmitPower_suite[i].test_name != NULL; i++) {
		hwr_gtp_case_t *test = &wifi_hal_getRadioTransmitPower_suite[i];

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
	printf("\nwifi_hal_getRadioTransmitPower: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
