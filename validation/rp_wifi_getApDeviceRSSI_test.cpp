/*
 * TEST RUNNER: rp_wifi_getApDeviceRSSI_test
 *
 * Same shape as the other *_test.cpp runners: test_rp_wifi_getApDeviceRSSI() POISONS what the function must not touch, calls the handler and unpoisons;
 * run_all_tests compares the result.  The runner owns the output slot (an INT at offset 16 of a 48-byte canary slab, preset to a stale value) and the 18-byte MAC
 * slab.  During the call it POISONS the WHOLE output slab and the WHOLE MAC slab (the stub must neither read nor write them: any access aborts under ASan), the guard
 * slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  Checks: return value 0; *output_RSSI still the stale value and the canary bytes unchanged; the MAC
 * slab unchanged; the guard slab unchanged; the log untouched.
 */
#include <stdio.h>
#include <string.h>
#include "hwr_rrs.h"
#include <sanitizer/asan_interface.h>

#define OFF 16
#define STALE (-77)
static unsigned char out_slab[48];
static char mac_slab[18];
static char log_before[HWR_LOG_SZ];

static void poison(int on, const hwr_rrs_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	if (t->out_mode == 1) fn(out_slab, sizeof(out_slab));
	if (t->mac_mode == 1) fn(mac_slab, sizeof(mac_slab));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison -- returns what the function returned (last call) */
int test_rp_wifi_getApDeviceRSSI(const hwr_rrs_case_t *t)
{
	CHAR *mac = t->mac_mode == 0 ? NULL : t->mac_mode == 1 ? mac_slab : (CHAR *)(unsigned long)0xdeadbeefUL;
	INT *out = t->out_mode == 0 ? NULL : t->out_mode == 1 ? (INT *)&out_slab[OFF] : (INT *)(unsigned long)0xdeadbeefUL;
	int ret = 0;

	poison(1, t);
	for (int i = 0; i < t->calls; i++) ret = hwr_rp_wifi_getApDeviceRSSI(t->ap_index, mac, out);
	poison(0, t);
	return ret;
}

static int check(const hwr_rrs_case_t *t, int ret, char *why, size_t wn)
{
	int got;

	if (ret != t->expected_ret) { snprintf(why, wn, "returned %d, expected %d", ret, t->expected_ret); return 0; }
	for (size_t k = 0; k < sizeof(out_slab); k++)
		if ((k < OFF || k >= OFF + sizeof(INT)) && out_slab[k] != 0x5A) { snprintf(why, wn, "canary byte %zu modified", k); return 0; }
	memcpy(&got, &out_slab[OFF], sizeof(got));
	if (got != STALE) { snprintf(why, wn, "*output_RSSI = %d, expected the stale value %d", got, STALE); return 0; }
	for (size_t k = 0; k < sizeof(mac_slab); k++) if (mac_slab[k] != 0x6B) { snprintf(why, wn, "MAC byte %zu modified", k); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, wn, "guard byte %d modified", k); return 0; }
	if (memcmp(hwr_log_buf, log_before, HWR_LOG_SZ) != 0) { snprintf(why, wn, "the log was modified (the function does not log)"); return 0; }
	return 1;
}

extern "C" void run_all_tests_rp_wifi_getApDeviceRSSI(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; rp_wifi_getApDeviceRSSI_suite[i].test_name != NULL; i++) {
		hwr_rrs_case_t *test = &rp_wifi_getApDeviceRSSI_suite[i];
		char why[160] = "";
		INT stale = STALE;

		printf("--- Running Test: %s ---\n", test->test_name);

		memset(hwr_log_buf, 0, HWR_LOG_SZ);
		memset(hwr_log_buf, 'x', test->prefill);
		memcpy(log_before, hwr_log_buf, HWR_LOG_SZ);
		memset(out_slab, 0x5A, sizeof(out_slab));
		memcpy(&out_slab[OFF], &stale, sizeof(stale));
		memset(mac_slab, 0x6B, sizeof(mac_slab));
		memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

		int ret = test_rp_wifi_getApDeviceRSSI(test);

		if (check(test, ret, why, sizeof(why))) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", test->test_name, test->expected_ret, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_getApDeviceRSSI (raspberry-pi): %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
