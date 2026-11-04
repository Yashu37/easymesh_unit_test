/*
 * TEST RUNNER: wifi_hal_getRadioChannelStats_test
 *
 * The runner owns the output array (hwr_arr_slab: room for exactly HAL_IPC_RADIO_CHANNELS_MAX entries),
 * POISONS its tail, calls the function, UNPOISONS and checks the result:
 *   hwr_arr_slab    : [64 * sizeof(wifi_channelStats_t), end)   - the 65th entry onwards
 *   hwr_log_buf     : [HWR_LOG_USE, HWR_LOG_SZ)
 * Rows flagged `forked` are expected to crash the unfixed function (NULL array): they run in a child so the
 * ASan report is visible but the run continues.  The function is NOT modified.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "hwr_grc.h"
#include <sanitizer/asan_interface.h>

#define CAP   HAL_IPC_RADIO_CHANNELS_MAX
#define PADB  (4 * sizeof(wifi_channelStats_t))
static unsigned char hwr_arr_slab[CAP * sizeof(wifi_channelStats_t) + PADB];

static void poison_all(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_arr_slab[CAP * sizeof(wifi_channelStats_t)], PADB);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static char why[200];

static int run_case(const hwr_grc_case_t *t)
{
	wifi_channelStats_t *arr = t->null_arr ? NULL : (wifi_channelStats_t *)hwr_arr_slab;
	INT ret = 0;

	why[0] = 0;
	memset(hwr_arr_slab, 0, sizeof(hwr_arr_slab));
	memset(hwr_log_buf, 0, HWR_LOG_USE);
	hwr_grc_configure(t->callee_ret);

	if (t->forked) {                                         /* SEGV report visible, run continues */
		int st; pid_t pid;
		fflush(stdout);
		poison_all(1);
		pid = fork();
		if (pid == 0) { ret = hwr_wifi_hal_getRadioChannelStats(t->radio_index, arr, t->array_size); _exit(ret == t->expected_ret ? 0 : 2); }
		waitpid(pid, &st, 0);
		poison_all(0);
		if (!WIFEXITED(st)) { snprintf(why, sizeof(why), "child died (SEGV on the NULL array)"); return 0; }
		if (WEXITSTATUS(st) != 0) { snprintf(why, sizeof(why), "child did not return an error for the NULL array"); return 0; }
		return 1;
	}

	for (int i = 0; i < t->calls; i++) {
		hwr_grc_configure(t->callee_ret);
		poison_all(1);
		ret = hwr_wifi_hal_getRadioChannelStats(t->radio_index, arr, t->array_size);
		poison_all(0);
		if (ret != t->expected_ret) { snprintf(why, sizeof(why), "call %d returned %d, expected %d", i, ret, t->expected_ret); return 0; }
		if (t->expected_fwd < 0) {
			if (hwr_grc_rec.calls != 0) { snprintf(why, sizeof(why), "platform function called with array_size %d (must be rejected first)", hwr_grc_rec.size); return 0; }
		} else {
			if (hwr_grc_rec.calls != 1) { snprintf(why, sizeof(why), "platform function called %d times", hwr_grc_rec.calls); return 0; }
			if (hwr_grc_rec.size != t->expected_fwd) { snprintf(why, sizeof(why), "platform got array_size %d, expected %d", hwr_grc_rec.size, t->expected_fwd); return 0; }
			if (hwr_grc_rec.radio != t->radio_index || hwr_grc_rec.arr != arr) { snprintf(why, sizeof(why), "radio / array not forwarded unchanged"); return 0; }
			if (hwr_arr_slab[0] != 0x5A || hwr_arr_slab[t->expected_fwd * sizeof(wifi_channelStats_t) - 1] != 0x5A) { snprintf(why, sizeof(why), "entries not filled"); return 0; }
		}
	}
	if (t->check_log == 1) { char w[40]; snprintf(w, sizeof(w), "Array size %d", t->array_size); if (!strstr(hwr_log_buf, w)) { snprintf(why, sizeof(why), "log lacks '%s': '%s'", w, hwr_log_buf); return 0; } }
	if (t->check_log == 2 && !strstr(hwr_log_buf, "Truncate")) { snprintf(why, sizeof(why), "log lacks the truncate notice: '%s'", hwr_log_buf); return 0; }
	return 1;
}

extern "C" void run_all_tests_wifi_hal_getRadioChannelStats(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; wifi_hal_getRadioChannelStats_suite[i].test_name != NULL; i++) {
		hwr_grc_case_t *test = &wifi_hal_getRadioChannelStats_suite[i];

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
	printf("\nwifi_hal_getRadioChannelStats: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
