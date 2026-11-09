/*
 * TEST RUNNER: bcm_wifi_getRadioTrafficStats2_test
 *
 * Same shape as the other *_test.cpp runners: test_bcm_wifi_getRadioTrafficStats2() POISONS what the function must not touch, calls the handler and
 * unpoisons; run_all_tests compares the result.  The runner owns the output structure: a heap block of exactly sizeof(wifi_radioTrafficStats2_t)
 * (ASan catches any access behind it), pre-filled with a stale pattern.  During the call it POISONS the guard slab and the log slot tail
 * [HWR_LOG_USE, HWR_LOG_SZ).
 * Checks: return value; the structure either equals its stale content (failed lookup / command / unparsable reply must not write it) or holds the 21
 * expected statistics (every field compared; padding stays stale); a second call (calls = 2) must give the same result.
 * Rows with last = 1 are the invalid-input rows that crash the original: they run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hwr_bgt.h"
#include <sanitizer/asan_interface.h>

static bgt_iface_t iface_obj;
static bgt_radio_t radio_obj;
static char why[200];

/* poison, call, unpoison -- returns what the function returned */
int test_bcm_wifi_getRadioTrafficStats2(const bgt_case_t *t, wifi_radioTrafficStats2_t *out)
{
	__asan_poison_memory_region(hwr_guard_slab, HWR_GUARD_SZ);
	__asan_poison_memory_region(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
	int ret = hwr_bcm_wifi_getRadioTrafficStats2(t->radio_index, out);
	__asan_unpoison_memory_region(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
	__asan_unpoison_memory_region(hwr_guard_slab, HWR_GUARD_SZ);
	return ret;
}

static void setup(const bgt_case_t *t)
{
	bgt_world_t *w = &hwr_bgt_world;

	memset(w, 0, sizeof(*w));
	memset(hwr_log_buf, 0, HWR_LOG_SZ);
	memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);
	memset(&iface_obj, 0, sizeof(iface_obj)); iface_obj.index = 7; iface_obj.phy_index = 1;
	radio_obj.rdk_index = 0; radio_obj.primary = t->has_iface ? &iface_obj : NULL;
	w->radio = t->has_radio ? &radio_obj : NULL;
	w->cmd_fail = t->cmd_fail; w->dump_rc = t->dump_rc; w->omit_reply = t->omit_reply; w->omit_attr = t->omit_attr; w->base = t->base;
}

static void expected(wifi_radioTrafficStats2_t *x, unsigned long long b)
{
	#define U(i) (b + (unsigned long long)(i))
	#define S(i) (-(50 + (i) + (int)(b & 7)))
	x->radio_BytesSent = U(1); x->radio_BytesReceived = U(2); x->radio_PacketsSent = U(3); x->radio_PacketsReceived = U(4);
	x->radio_ErrorsSent = U(5); x->radio_ErrorsReceived = U(6); x->radio_DiscardPacketsSent = U(7); x->radio_DiscardPacketsReceived = U(8);
	x->radio_PLCPErrorCount = U(9); x->radio_FCSErrorCount = U(10); x->radio_InvalidMACCount = U(11); x->radio_PacketsOtherReceived = U(12);
	x->radio_NoiseFloor = S(13); x->radio_ChannelUtilization = U(14); x->radio_ActivityFactor = S(15);
	x->radio_CarrierSenseThreshold_Exceeded = S(16); x->radio_RetransmissionMetirc = S(17); x->radio_MaximumNoiseFloorOnChannel = S(18);
	x->radio_MinimumNoiseFloorOnChannel = S(19); x->radio_MedianNoiseFloorOnChannel = S(20); x->radio_StatisticsStartTime = U(21);
}

#define CHK(cond, ...) do { if (!(cond)) { snprintf(why, sizeof(why), __VA_ARGS__); return 0; } } while (0)

/* one call; returns 1 if everything holds.  *got receives the return value */
static int one_call(const bgt_case_t *t, wifi_radioTrafficStats2_t *blk, int *got)
{
	wifi_radioTrafficStats2_t x;
	int ret = test_bcm_wifi_getRadioTrafficStats2(t, t->out_mode ? blk : NULL);
	/* the handler ran when the command was sent and the reply was complete */
	int reached = t->has_radio && t->has_iface && t->radio_index == 0 && !t->cmd_fail && t->omit_reply == 0 && t->omit_attr == 0;

	*got = ret;
	CHK(ret == t->expected_ret, "returned %d, expected %d", ret, t->expected_ret);
	if (!t->out_mode) return 1;
	memset(&x, 0x5A, sizeof(x));
	if (reached) expected(&x, t->base);
	CHK(memcmp(blk, &x, sizeof(x)) == 0, "%s", reached ? "statistics do not match the kernel reply" : "output structure was written although no statistics were delivered");
	return 1;
}

static int run_one(const bgt_case_t *t)
{
	int ok, got = 0;
	wifi_radioTrafficStats2_t *blk = t->out_mode ? (wifi_radioTrafficStats2_t *)malloc(sizeof(*blk)) : NULL;

	printf("--- Running Test: %s ---\n", t->test_name);
	setup(t);
	why[0] = 0;
	if (blk) memset(blk, 0x5A, sizeof(*blk));
	ok = one_call(t, blk, &got);
	if (ok && t->calls > 1) { int r2; ok = one_call(t, blk, &r2); }
	free(blk);
	if (ok) {
		printf("================== %s: \033[32mPASS\033[0m ==============\n", t->test_name);
	} else {
		printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", t->test_name, t->expected_ret, got, why);
	}
	printf("------------------------------------------------------------------------------------------------------------------------------\n");
	return ok;
}

extern "C" void run_all_tests_bcm_wifi_getRadioTrafficStats2(void)
{
	int pass = 0, fail = 0;

	/* normal rows first, invalid / failure rows last: the first crash aborts the run, every other row has already reported */
	for (int last = 0; last < 2; last++)
		for (int i = 0; bcm_wifi_getRadioTrafficStats2_suite[i].test_name != NULL; i++) {
			if (bcm_wifi_getRadioTrafficStats2_suite[i].last != last) continue;
			if (run_one(&bcm_wifi_getRadioTrafficStats2_suite[i])) pass++; else fail++;
		}
	printf("\nwifi_getRadioTrafficStats2 (broadcom): %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
