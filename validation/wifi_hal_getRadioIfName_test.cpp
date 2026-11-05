/*
 * TEST RUNNER: wifi_hal_getRadioIfName_test
 *
 * The runner sets g_wifi_hal.num_radios, owns the caller's output buffer in a slab, POISONS its tail and the unused
 * log slot, calls the function, UNPOISONS and checks the result:
 *   hwr_out_slab : [HAL_IPC_MAX_STRING_LEN, end)    the caller's buffer is 64 bytes, nothing behind it
 *   hwr_log_buf  : [HWR_LOG_USE, HWR_LOG_SZ)
 * The output buffer is preset to 0xA5.  The static table cloud_radio_map (two entries) has ASan's own global red
 * zones, so a read of cloud_radio_map[2] is reported as a global-buffer-overflow.  Rows flagged `forked` read outside
 * the table in the unfixed function: they run in a child so the ASan report is visible but the run continues.
 * The function is NOT modified.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "hwr_gri.h"
#include <sanitizer/asan_interface.h>

#define OUT_CAP HAL_IPC_MAX_STRING_LEN
static unsigned char hwr_out_slab[OUT_CAP + 64];

static void poison_all(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_out_slab[OUT_CAP], sizeof(hwr_out_slab) - OUT_CAP);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static char why[220];

static int run_case(const hwr_gri_case_t *t)
{
	CHAR *out = t->null_out ? NULL : (CHAR *)hwr_out_slab;
	INT ret = 0;

	why[0] = 0;
	hwr_gri_world.num_radios = t->num_radios;
	memset(hwr_out_slab, 0xA5, sizeof(hwr_out_slab)); memset(hwr_log_buf, 0, HWR_LOG_USE);

	if (t->forked) {                                         /* ASan report visible, run continues */
		int st; pid_t pid;
		fflush(stdout);
		poison_all(1);
		pid = fork();
		if (pid == 0) { ret = hwr_wifi_hal_getRadioIfName(t->index, out); _exit(ret == t->expected_ret ? 0 : 2); }
		waitpid(pid, &st, 0);
		poison_all(0);
		if (!WIFEXITED(st)) { snprintf(why, sizeof(why), "child died (read outside cloud_radio_map)"); return 0; }
		if (WEXITSTATUS(st) == 1) { snprintf(why, sizeof(why), "child aborted by AddressSanitizer (global-buffer-overflow: cloud_radio_map has 2 entries, index %d, num_radios %u)", t->index, t->num_radios); return 0; }
		if (WEXITSTATUS(st) != 0) { snprintf(why, sizeof(why), "child did not return the expected result (exit %d)", WEXITSTATUS(st)); return 0; }
		return 1;
	}

	for (int i = 0; i < t->calls; i++) {
		memset(hwr_out_slab, 0xA5, sizeof(hwr_out_slab)); memset(hwr_log_buf, 0, HWR_LOG_USE);
		poison_all(1);
		ret = hwr_wifi_hal_getRadioIfName(t->index, out);
		poison_all(0);
		if (ret != t->expected_ret) {
			snprintf(why, sizeof(why), "call %d returned %d, expected %d%s", i, ret, t->expected_ret,
			         (ret == 0 && t->expected_ret != 0) ? " (an index that is not a radio was accepted: off-by-one `>` against num_radios)" : "");
			return 0;
		}
		if (t->expected_out == NULL) {
			for (int k = 0; k < OUT_CAP && !t->null_out; k++) if (hwr_out_slab[k] != 0xA5) { snprintf(why, sizeof(why), "output byte %d written although the call failed", k); return 0; }
		} else {
			size_t want = strlen(t->expected_out);
			if (strcmp((char *)hwr_out_slab, t->expected_out)) { snprintf(why, sizeof(why), "output '%.20s', expected '%s'", (char *)hwr_out_slab, t->expected_out); return 0; }
			for (size_t k = want + 1; k < sizeof(hwr_out_slab); k++) if (hwr_out_slab[k] != 0xA5) { snprintf(why, sizeof(why), "byte %zu behind the string modified", k); return 0; }
		}
	}
	if (t->check_log == 1 && (!strstr(hwr_log_buf, "wifi_hal_getRadioIfName") || !strstr(hwr_log_buf, "Requested radio index 1 GW name wlan2 translated to cloud name wl1"))) { snprintf(why, sizeof(why), "log lacks the translation line: '%.150s'", hwr_log_buf); return 0; }
	if (t->check_log == 2 && !strstr(hwr_log_buf, "radio index 3 out of range")) { snprintf(why, sizeof(why), "log lacks the out of range line: '%.150s'", hwr_log_buf); return 0; }
	return 1;
}

extern "C" void run_all_tests_wifi_hal_getRadioIfName(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; wifi_hal_getRadioIfName_suite[i].test_name != NULL; i++) {
		hwr_gri_case_t *test = &wifi_hal_getRadioIfName_suite[i];

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
	printf("\nwifi_hal_getRadioIfName: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
