/*
 * TEST RUNNER: wifi_getRadioChannelStats_test
 *
 * Same shape as the other *_test.cpp runners: test_wifi_getRadioChannelStats() POISONS what the function must not touch, calls the handler and
 * unpoisons; run_all_tests compares the result.  The runner owns the caller's array: GKS_N (64) wifi_channelStats_t entries with the channel numbers
 * pre-filled (1..64) and every other byte stale (0x5A), followed by a 256-byte slab.  During the call it POISONS everything behind the entries the call
 * may use (the tail [max(array_size, 1), 64), the slab behind the array), the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ): a write
 * past the requested entries aborts under ASan.  Checks: the return value (WIFI_HAL_ERROR: the stub has no statistics, success would make the
 * caller read stale values), the array bytes unchanged (nothing fabricated), the guard slab and the log untouched.
 */
#include <stdio.h>
#include <string.h>
#include "hwr_gks.h"
#include <sanitizer/asan_interface.h>

static wifi_channelStats_t arr[GKS_N];
static unsigned char behind[256];
static wifi_channelStats_t before[GKS_N];
static char why[200];

static unsigned used_entries(const hwr_gks_case_t *t)
{
	unsigned n = (t->array_size <= 0) ? 1u : (unsigned)t->array_size;
	return n > GKS_N ? GKS_N : n;
}

static void poison(int on, const hwr_gks_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	if (t->array_mode) {
		unsigned n = used_entries(t);
		fn(&arr[n], (GKS_N - n) * sizeof(arr[0]));
		fn(behind, sizeof(behind));
	}
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison -- returns what the function returned (last call) */
static int test_wifi_getRadioChannelStats(const hwr_gks_case_t *t)
{
	wifi_channelStats_t *a = t->array_mode ? arr : NULL;
	int ret = 0;

	poison(1, t);
	for (int i = 0; i < t->calls; i++) ret = hwr_wifi_getRadioChannelStats(t->radio_index, a, t->array_size);
	poison(0, t);
	return ret;
}

static int check(const hwr_gks_case_t *t, int ret)
{
	if (ret != t->expected_ret) { snprintf(why, sizeof(why), "returned %d (success), expected %d: no statistics were filled in", ret, t->expected_ret); return 0; }
	if (t->array_mode && memcmp(arr, before, sizeof(arr)) != 0) { snprintf(why, sizeof(why), "the array was modified"); return 0; }
	for (size_t k = 0; k < sizeof(behind); k++) if (behind[k] != 0x5A) { snprintf(why, sizeof(why), "byte %zu behind the array modified", k); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", k); return 0; }
	for (int k = 0; k < HWR_LOG_SZ; k++) if (hwr_log_buf[k] != 0) { snprintf(why, sizeof(why), "the log was modified"); return 0; }
	return 1;
}

extern "C" void run_all_tests_wifi_getRadioChannelStats(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; wifi_getRadioChannelStats_suite[i].test_name != NULL; i++) {
		hwr_gks_case_t *test = &wifi_getRadioChannelStats_suite[i];

		printf("--- Running Test: %s ---\n", test->test_name);

		memset(hwr_log_buf, 0, HWR_LOG_SZ);
		memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);
		memset(arr, 0x5A, sizeof(arr));
		for (int k = 0; k < GKS_N; k++) arr[k].ch_number = k + 1;
		memset(behind, 0x5A, sizeof(behind));
		memcpy(before, arr, sizeof(arr));

		why[0] = 0;
		int ret = test_wifi_getRadioChannelStats(test);

		if (check(test, ret)) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", test->test_name, test->expected_ret, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_getRadioChannelStats: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
