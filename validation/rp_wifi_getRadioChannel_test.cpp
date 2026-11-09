/*
 * TEST RUNNER: rp_wifi_getRadioChannel_test
 *
 * Same shape as the other *_test.cpp runners: test_rp_wifi_getRadioChannel() POISONS what the function must not touch, calls the handler and unpoisons;
 * run_all_tests compares the result.  The runner owns the output slot: a 48-byte canary slab (0x5A) with the 8-byte ULONG at offset 16 holding a stale value.
 * During the call it POISONS the WHOLE slab (the stub must neither read nor write the ULONG: any access aborts under ASan), the guard slab and the log slot tail
 * [HWR_LOG_USE, HWR_LOG_SZ).  Checks: return value 0; *output_ulong still the stale value and the canary bytes unchanged; the guard slab unchanged; the log untouched.
 */
#include <stdio.h>
#include <string.h>
#include "hwr_rgc.h"
#include <sanitizer/asan_interface.h>

#define OFF 16
#define STALE 0x1122334455667788UL
static unsigned char slab[48];
static char log_before[HWR_LOG_SZ];

static void poison(int on, const hwr_rgc_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	if (t->out_mode == 1) fn(slab, sizeof(slab));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison -- returns what the function returned (last call) */
int test_rp_wifi_getRadioChannel(const hwr_rgc_case_t *t)
{
	ULONG *out = t->out_mode == 0 ? NULL : t->out_mode == 1 ? (ULONG *)&slab[OFF] : (ULONG *)(unsigned long)0xdeadbeefUL;
	int ret = 0;

	poison(1, t);
	for (int i = 0; i < t->calls; i++) ret = hwr_rp_wifi_getRadioChannel(t->radio_index, out);
	poison(0, t);
	return ret;
}

static int check(const hwr_rgc_case_t *t, int ret, char *why, size_t wn)
{
	ULONG got;

	if (ret != t->expected_ret) { snprintf(why, wn, "returned %d, expected %d", ret, t->expected_ret); return 0; }
	for (size_t k = 0; k < sizeof(slab); k++)
		if ((k < OFF || k >= OFF + sizeof(ULONG)) && slab[k] != 0x5A) { snprintf(why, wn, "canary byte %zu modified", k); return 0; }
	memcpy(&got, &slab[OFF], sizeof(got));
	if (got != STALE) { snprintf(why, wn, "*output_ulong = %lu, expected the stale value %lu", got, (ULONG)STALE); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, wn, "guard byte %d modified", k); return 0; }
	if (memcmp(hwr_log_buf, log_before, HWR_LOG_SZ) != 0) { snprintf(why, wn, "the log was modified (the function does not log)"); return 0; }
	return 1;
}

extern "C" void run_all_tests_rp_wifi_getRadioChannel(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; rp_wifi_getRadioChannel_suite[i].test_name != NULL; i++) {
		hwr_rgc_case_t *test = &rp_wifi_getRadioChannel_suite[i];
		char why[160] = "";
		ULONG stale = STALE;

		printf("--- Running Test: %s ---\n", test->test_name);

		memset(hwr_log_buf, 0, HWR_LOG_SZ);
		memset(hwr_log_buf, 'x', test->prefill);
		memcpy(log_before, hwr_log_buf, HWR_LOG_SZ);
		memset(slab, 0x5A, sizeof(slab));
		memcpy(&slab[OFF], &stale, sizeof(stale));
		memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

		int ret = test_rp_wifi_getRadioChannel(test);

		if (check(test, ret, why, sizeof(why))) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", test->test_name, test->expected_ret, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_getRadioChannel (raspberry-pi): %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
