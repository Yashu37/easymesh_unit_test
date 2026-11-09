/*
 * TEST RUNNER: int_wifi_getRadioChannel_test
 *
 * Same shape as the other *_test.cpp runners: test_int_wifi_getRadioChannel() POISONS what the function must not touch, calls the handler and unpoisons;
 * run_all_tests compares the result.  The runner owns the output slot: a 48-byte canary slab (0x5A) with the 8-byte ULONG at offset 16, like a member inside a
 * larger struct, holding a stale value.  During the call it POISONS the head [0, 16) and the tail [24, 48) of the slab (so a write of more than 8 bytes or at a
 * wrong offset aborts under ASan), the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  The radio object itself is not poisoned (the function reads it).
 * Checks: return value; *output_ulong == the radio's channel on success / still the stale value otherwise; the canary bytes unchanged; the lookup was done once per
 * call with the same index; the guard slab unchanged; the log untouched (the function does not log).
 * Rows with last = 1 are the invalid-input rows that crash the original: they run LAST.
 */
#include <stdio.h>
#include <string.h>
#include "hwr_igc.h"
#include <sanitizer/asan_interface.h>

#define OFF 16
#define STALE 0x5A5A5A5A5A5A5A5AUL
static unsigned char slab[48];
static igc_radio_t radio_obj;
static char log_before[HWR_LOG_SZ];
static char why[200];

static void poison(int on, int out_mode)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	if (out_mode) {
		fn(&slab[0], OFF);
		fn(&slab[OFF + sizeof(ULONG)], sizeof(slab) - OFF - sizeof(ULONG));
	}
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison -- returns what the function returned (last call) */
int test_int_wifi_getRadioChannel(const hwr_igc_case_t *t)
{
	ULONG *out = t->out_mode ? (ULONG *)&slab[OFF] : NULL;
	int ret = 0;

	poison(1, t->out_mode);
	for (int i = 0; i < t->calls; i++) ret = hwr_int_wifi_getRadioChannel(t->radio_index, out);
	poison(0, t->out_mode);
	return ret;
}

static int check(const hwr_igc_case_t *t, int ret)
{
	hwr_igc_world_t *w = &hwr_igc_world;
	ULONG got;
	ULONG expect = t->expected_ret == RETURN_OK ? (ULONG)t->channel : STALE;

	if (ret != t->expected_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, t->expected_ret); return 0; }
	if (w->lookups != t->calls || w->last_lookup != t->radio_index) { snprintf(why, sizeof(why), "%d lookups (last index %d), expected %d for index %d", w->lookups, w->last_lookup, t->calls, t->radio_index); return 0; }
	for (int k = 0; k < (int)sizeof(slab); k++)
		if ((k < OFF || k >= OFF + (int)sizeof(ULONG)) && slab[k] != 0x5A) { snprintf(why, sizeof(why), "canary byte %d modified", k); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", k); return 0; }
	if (memcmp(hwr_log_buf, log_before, HWR_LOG_SZ) != 0) { snprintf(why, sizeof(why), "the log was modified (the function does not log)"); return 0; }
	if (t->out_mode) {
		memcpy(&got, &slab[OFF], sizeof(got));
		if (got != expect) { snprintf(why, sizeof(why), "*output_ulong = %lu, expected %lu (%s)", got, expect, t->expected_ret == RETURN_OK ? "the channel" : "stale value, must stay"); return 0; }
	}
	return 1;
}

static int run_one(const hwr_igc_case_t *t)
{
	printf("--- Running Test: %s ---\n", t->test_name);

	memset(&hwr_igc_world, 0, sizeof(hwr_igc_world));
	memset(&radio_obj, 0, sizeof(radio_obj));
	radio_obj.configured = t->configured != 0;
	radio_obj.oper_param.enable = (BOOL)t->enable;
	radio_obj.oper_param.channel = t->channel;
	if (t->has_radio) {
		hwr_igc_world.radio = &radio_obj;
		hwr_igc_world.radio_rdk_index = t->has_radio == 1 ? t->radio_index : (int)((unsigned)t->radio_index + 1u);
	}
	memset(hwr_log_buf, 0, HWR_LOG_SZ);
	memcpy(log_before, hwr_log_buf, HWR_LOG_SZ);
	memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);
	memset(slab, 0x5A, sizeof(slab));

	why[0] = 0;
	int ret = test_int_wifi_getRadioChannel(t);
	int ok = check(t, ret);

	if (ok) {
		printf("================== %s: \033[32mPASS\033[0m ==============\n", t->test_name);
	} else {
		printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", t->test_name, t->expected_ret, ret, why);
	}
	printf("------------------------------------------------------------------------------------------------------------------------------\n");
	return ok;
}

extern "C" void run_all_tests_int_wifi_getRadioChannel(void)
{
	int pass = 0, fail = 0;

	/* normal rows first, invalid rows last: the first crash aborts the run, every other row has already reported */
	for (int last = 0; last < 2; last++)
		for (int i = 0; int_wifi_getRadioChannel_suite[i].test_name != NULL; i++) {
			if (int_wifi_getRadioChannel_suite[i].last != last) continue;
			if (run_one(&int_wifi_getRadioChannel_suite[i])) pass++; else fail++;
		}
	printf("\nwifi_getRadioChannel (intel): %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
