/*
 * TEST RUNNER: sg_wifi_storeInitialPassPointSettings_test
 *
 * test_sg_wifi_storeInitialPassPointSettings() POISONS what the function must not touch, calls the handler and unpoisons: hs2Settings[MAX_AP_INDEX] (the 16th slot, one past the last ap index it may write),
 * hs2SettingsStored, the world's unrelated members, the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  The static array is prefilled with a sentinel so untouched slots are detectable.
 * run_all_tests compares the result with a reference model of the CORRECT behaviour (see the construct file): stored values for ap 0 .. 14, getter call order / counts / non-NULL output pointers, debug
 * prints, untouched slot 15 and flag, guard slab unchanged.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hwr_wsp.h"
#include <sanitizer/asan_interface.h>

static char why[240];

static BOOL value_of(int pattern, int kind, int ap)
{
	switch (pattern) {
	case 0: return 0;
	case 1: return 1;
	case 2: return (BOOL)((ap + kind) & 1);
	case 3: return 2;
	default: return (BOOL)0xFF;
	}
}

static void fill_values(int pattern)
{
	for (int k = 0; k < 5; k++) for (int a = 0; a < HWR_WSP_MAXAP; a++) hwr_wsp_world.val[k][a] = value_of(pattern, k, a);
}

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	int n; wifi_HS2Settings_t *h = hwr_wsp_hs2(&n);

	fn(&h[HWR_WSP_MAXAP], sizeof(h[HWR_WSP_MAXAP]));
	fn(hwr_wsp_stored(), sizeof(BOOL));
	fn(hwr_wsp_world.unrelated, sizeof(hwr_wsp_world.unrelated));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison (once per call) */
static void test_sg_wifi_storeInitialPassPointSettings(const hwr_wsp_case_t *t)
{
	poison(1);
	hwr_sg_wifi_storeInitialPassPointSettings();
	poison(0);
	if (t->pattern2 >= 0) {
		fill_values(t->pattern2);
		poison(1);
		hwr_sg_wifi_storeInitialPassPointSettings();
		poison(0);
	}
}

static int check(const hwr_wsp_case_t *t)
{
	const hwr_wsp_world_t *w = &hwr_wsp_world;
	int n; wifi_HS2Settings_t *h = hwr_wsp_hs2(&n);
	int ncalls = (t->pattern2 >= 0) ? 2 : 1;
	int final_pattern = (t->pattern2 >= 0) ? t->pattern2 : t->pattern;

	for (int k = 0; k < 5; k++) if (w->calls[k] != HWR_WSP_MAXAP * ncalls) { snprintf(why, sizeof(why), "getter %d called %d times, expected %d", k, w->calls[k], HWR_WSP_MAXAP * ncalls); return 0; }
	if (w->null_out != 0) { snprintf(why, sizeof(why), "a getter got a NULL output pointer"); return 0; }
	for (int i = 0; i < w->seq_n && i < 5 * HWR_WSP_MAXAP; i++) {
		if (w->seq_kind[i] != i % 5 || w->seq_ap[i] != i / 5) { snprintf(why, sizeof(why), "getter call %d was (kind %d, ap %d), expected (kind %d, ap %d)", i, w->seq_kind[i], w->seq_ap[i], i % 5, i / 5); return 0; }
	}
	if (w->dbg_calls != HWR_WSP_MAXAP * ncalls) { snprintf(why, sizeof(why), "%d debug prints, expected %d", w->dbg_calls, HWR_WSP_MAXAP * ncalls); return 0; }
	for (int a = 0; a < HWR_WSP_MAXAP && a < (int)(sizeof(w->dbg_ap) / sizeof(int)); a++) if (w->dbg_ap[a] != a) { snprintf(why, sizeof(why), "debug print %d shows ap %d", a, w->dbg_ap[a]); return 0; }
	for (int a = 0; a < HWR_WSP_MAXAP; a++) {
		BOOL got[5] = { h[a].countryIe, h[a].layer2TIF, h[a].downStreamGroupAddress, h[a].bssLoad, h[a].proxyArp };
		for (int k = 0; k < 5; k++) {
			if (k == t->fail_kind) continue;     /* a failing getter leaves its own field unspecified */
			if (got[k] != value_of(final_pattern, k, a)) { snprintf(why, sizeof(why), "hs2Settings[%d] field %d is %u, expected %u", a, k, (unsigned)got[k], (unsigned)value_of(final_pattern, k, a)); return 0; }
		}
	}
	{
		unsigned char *s = (unsigned char *)&h[HWR_WSP_MAXAP];
		for (size_t b = 0; b < sizeof(h[0]); b++) if (s[b] != 0x77) { snprintf(why, sizeof(why), "hs2Settings[%d] was modified", HWR_WSP_MAXAP); return 0; }
	}
	if (*hwr_wsp_stored() != (BOOL)0x55) { snprintf(why, sizeof(why), "hs2SettingsStored modified"); return 0; }
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

static void setup(const hwr_wsp_case_t *t)
{
	int n; wifi_HS2Settings_t *h = hwr_wsp_hs2(&n);

	memset(&hwr_wsp_world, 0, sizeof(hwr_wsp_world));
	hwr_wsp_world.fail_kind = t->fail_kind;
	fill_values(t->pattern);
	memset(h, 0x77, sizeof(*h) * n);
	memset(hwr_wsp_stored(), 0x55, sizeof(BOOL));
}

extern "C" void run_all_tests_sg_wifi_storeInitialPassPointSettings(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_storeInitialPassPointSettings_suite[i].test_name != NULL; i++) {
			hwr_wsp_case_t *test = &sg_wifi_storeInitialPassPointSettings_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_storeInitialPassPointSettings(test);

			int ok = check(test);
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_storeInitialPassPointSettings: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
