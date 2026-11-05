/*
 * TEST RUNNER: platform_wps_event_test
 *
 * The event is passed by value, so the only memory the function could touch besides the log is what event.wps_data points to.  The runner
 * owns that memory in a slab (hwr_wps_slab) and POISONS ALL of it during the call (data_mode 1): any read or write of it aborts under ASan.
 * The log slot tail [HWR_LOG_USE, HWR_LOG_SZ) is poisoned too.  After the calls it checks the return value (0), that the log was only appended
 * inside the first HWR_LOG_USE bytes with the previous text intact, that (expect_log) one "platform_wps_event:<line> " line per call was
 * appended, and that the slab is unchanged.
 */
#include <stdio.h>
#include <string.h>
#include "hwr_pwe.h"
#include <sanitizer/asan_interface.h>

static unsigned char hwr_wps_slab[256];

static int run_case(const hwr_pwe_case_t *t, char *why, size_t wn)
{
	int ret = 0, n = 0;
	const char *p;
	wifi_wps_event_t ev;

	memset(hwr_log_buf, 0, HWR_LOG_SZ);
	memset(hwr_log_buf, 'x', t->prefill);
	memset(hwr_wps_slab, 0xA5, sizeof(hwr_wps_slab));
	ev.vap_index = t->vap_index; ev.event = t->event;
	ev.wps_data = t->data_mode == 0 ? NULL : t->data_mode == 1 ? hwr_wps_slab : (unsigned char *)(unsigned long)0xdeadbeefUL;
	if (t->data_mode == 1) __asan_poison_memory_region(hwr_wps_slab, sizeof(hwr_wps_slab));
	__asan_poison_memory_region(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
	for (int i = 0; i < t->calls; i++) ret = hwr_platform_wps_event(ev);
	__asan_unpoison_memory_region(hwr_wps_slab, sizeof(hwr_wps_slab));
	__asan_unpoison_memory_region(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);

	if (ret != t->expected_ret) { snprintf(why, wn, "returned %d, expected %d", ret, t->expected_ret); return 0; }
	for (int i = 0; i < t->prefill; i++) if (hwr_log_buf[i] != 'x') { snprintf(why, wn, "previous log byte %d modified", i); return 0; }
	for (int i = HWR_LOG_USE; i < HWR_LOG_SZ; i++) if (hwr_log_buf[i] != 0) { snprintf(why, wn, "log byte %d behind HWR_LOG_USE written", i); return 0; }
	for (size_t k = 0; k < sizeof(hwr_wps_slab); k++) if (hwr_wps_slab[k] != 0xA5) { snprintf(why, wn, "wps_data byte %zu modified", k); return 0; }
	if (t->expect_log) {
		for (p = hwr_log_buf + t->prefill; (p = strstr(p, "platform_wps_event:")) != NULL; p++) n++;
		if (n != t->calls) { snprintf(why, wn, "%d log lines, expected %d", n, t->calls); return 0; }
		if (hwr_log_buf[strlen(hwr_log_buf) - 1] != '\n') { snprintf(why, wn, "log line not newline terminated"); return 0; }
	}
	return 1;
}

extern "C" void run_all_tests_platform_wps_event(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; platform_wps_event_suite[i].test_name != NULL; i++) {
		hwr_pwe_case_t *test = &platform_wps_event_suite[i];
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
	printf("\nplatform_wps_event: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
