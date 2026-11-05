/*
 * TEST RUNNER: nvram_get_current_security_mode_test
 *
 * The runner owns *security_mode in a slab (hwr_out_slab, preset 0xA5) and POISONS everything behind the enum (bytes
 * [sizeof(wifi_security_modes_t), end)); the log slot tail [HWR_LOG_USE, HWR_LOG_SZ) is poisoned too.  After the call(s) it checks the return
 * value, that the enum is untouched (0xA5 - the unfixed function never writes it but reports success), that the previous log text
 * is intact, that exactly one "nvram_get_current_security_mode:<line> " line per call was appended when it fits, and that nothing was
 * written behind HWR_LOG_USE.
 */
#include <stdio.h>
#include <string.h>
#include "hwr_nsm.h"
#include <sanitizer/asan_interface.h>

static unsigned char hwr_out_slab[64];

static int run_case(const hwr_nsm_case_t *t, char *why, size_t wn)
{
	int ret = 0, n = 0;
	const char *p;
	wifi_security_modes_t *out = t->out_null ? NULL : (wifi_security_modes_t *)hwr_out_slab;

	memset(hwr_log_buf, 0, HWR_LOG_SZ);
	memset(hwr_log_buf, 'x', t->prefill);
	memset(hwr_out_slab, 0xA5, sizeof(hwr_out_slab));
	__asan_poison_memory_region(&hwr_out_slab[sizeof(wifi_security_modes_t)], sizeof(hwr_out_slab) - sizeof(wifi_security_modes_t));
	__asan_poison_memory_region(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
	for (int i = 0; i < t->calls; i++) ret = hwr_nvram_get_current_security_mode(out, t->vap_index);
	__asan_unpoison_memory_region(&hwr_out_slab[sizeof(wifi_security_modes_t)], sizeof(hwr_out_slab) - sizeof(wifi_security_modes_t));
	__asan_unpoison_memory_region(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);

	if (ret != t->expected_ret) { snprintf(why, wn, "returned %d, expected %d%s", ret, t->expected_ret, ret == 0 ? " (success reported, *security_mode never written)" : ""); return 0; }
	for (size_t k = 0; k < sizeof(wifi_security_modes_t); k++) if (hwr_out_slab[k] != 0xA5) { snprintf(why, wn, "*security_mode byte %zu written (0x%02x)", k, hwr_out_slab[k]); return 0; }
	for (int i = 0; i < t->prefill; i++) if (hwr_log_buf[i] != 'x') { snprintf(why, wn, "previous log byte %d modified", i); return 0; }
	for (int i = HWR_LOG_USE; i < HWR_LOG_SZ; i++) if (hwr_log_buf[i] != 0) { snprintf(why, wn, "log byte %d behind HWR_LOG_USE written", i); return 0; }
	if (t->prefill + 40 < HWR_LOG_USE) {
		for (p = hwr_log_buf + t->prefill; (p = strstr(p, "nvram_get_current_security_mode:")) != NULL; p++) n++;
		if (n != t->calls) { snprintf(why, wn, "%d log lines, expected %d", n, t->calls); return 0; }
	}
	return 1;
}

extern "C" void run_all_tests_nvram_get_current_security_mode(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; nvram_get_current_security_mode_suite[i].test_name != NULL; i++) {
		hwr_nsm_case_t *test = &nvram_get_current_security_mode_suite[i];
		char why[160] = "";

		printf("--- Running Test: %s ---\n", test->test_name);

		int ret = run_case(test, why, sizeof(why));

		if (ret == 1) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=1, got=%d) %s =====\n", test->test_name, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nnvram_get_current_security_mode: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
