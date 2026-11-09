/*
 * TEST RUNNER: bcm_wifi_getRadioTransmitPower_test
 *
 * Same shape as the other *_test.cpp runners: test_wifi_getRadioTransmitPower_bcm() POISONS what the wrapper must not touch, calls the handler and
 * unpoisons; run_all_tests compares the result.  The runner owns the output slot (a ULONG with a sentinel value) and POISONS it (mode 1) together with
 * the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ) during the call: the wrapper only forwards the pointer, so any read or write of the
 * slot aborts under ASan.  Mode 3 gives the core an unpoisoned slot it writes 37 into.
 * Checks: the core stub was called once per call with the same radioIndex and pointer, the return value equals the core result, nothing is logged, the
 * slot keeps its sentinel value (modes 1) / receives the core's value unchanged (mode 3), the guard slab is unchanged.
 */
#include <stdio.h>
#include <string.h>
#include "hwr_bgp.h"
#include <sanitizer/asan_interface.h>

static ULONG tx_slot;
static char log_before[HWR_LOG_SZ];
#define SENT_TX 0xDEADBEEFUL

static void poison(int on, const hwr_bgp_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	if (t->tx_mode == 1) fn(&tx_slot, sizeof(tx_slot));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static ULONG *ptr_of(int mode) { return mode == 0 ? NULL : (mode == 1 || mode == 3) ? &tx_slot : (ULONG *)(unsigned long)0xdeadbeefUL; }

/* poison, call, unpoison -- returns what the wrapper returned (last call) */
int test_wifi_getRadioTransmitPower_bcm(const hwr_bgp_case_t *t, ULONG *tx)
{
	int ret = 0;

	poison(1, t);
	for (int i = 0; i < t->calls; i++) ret = hwr_bcm_wifi_getRadioTransmitPower(t->radio_index, tx);
	poison(0, t);
	return ret;
}

static int check(const hwr_bgp_case_t *t, int ret, ULONG *tx, char *why, size_t wn)
{
	const hwr_bgp_world_t *w = &hwr_bgp_world;

	if (ret != t->core_ret) { snprintf(why, wn, "returned %d, the core returned %d", ret, t->core_ret); return 0; }
	if (w->calls != t->calls) { snprintf(why, wn, "core called %d times, expected %d", w->calls, t->calls); return 0; }
	if (w->last_radio != t->radio_index || w->last_tx != tx) { snprintf(why, wn, "arguments not forwarded unchanged"); return 0; }
	if (memcmp(hwr_log_buf, log_before, HWR_LOG_SZ) != 0) { snprintf(why, wn, "unexpected log output"); return 0; }
	if (t->tx_mode == 3) { if (tx_slot != 37) { snprintf(why, wn, "value written by the core changed: %lu", tx_slot); return 0; } }
	else if (tx_slot != SENT_TX) { snprintf(why, wn, "output slot modified"); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, wn, "guard byte %d modified", k); return 0; }
	return 1;
}

extern "C" void run_all_tests_wifi_getRadioTransmitPower_bcm(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; wifi_getRadioTransmitPower_bcm_suite[i].test_name != NULL; i++) {
		hwr_bgp_case_t *test = &wifi_getRadioTransmitPower_bcm_suite[i];
		char why[160] = "";

		printf("--- Running Test: %s ---\n", test->test_name);

		memset(&hwr_bgp_world, 0, sizeof(hwr_bgp_world));
		hwr_bgp_world.ret = test->core_ret;
		if (test->tx_mode == 3) { hwr_bgp_world.write_out = 1; hwr_bgp_world.write_value = 37; }
		memset(hwr_log_buf, 0, HWR_LOG_SZ);
		memcpy(log_before, hwr_log_buf, HWR_LOG_SZ);
		memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);
		tx_slot = SENT_TX;

		ULONG *tx = ptr_of(test->tx_mode);
		int ret = test_wifi_getRadioTransmitPower_bcm(test, tx);

		if (check(test, ret, tx, why, sizeof(why))) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", test->test_name, test->core_ret, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_getRadioTransmitPower (broadcom): %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
