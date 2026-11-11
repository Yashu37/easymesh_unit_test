/*
 * TEST RUNNER: sg_wifi_hal_set_neighbor_report_test
 *
 * test_sg_wifi_hal_set_neighbor_report() POISONS what the function must not touch, calls the handler and unpoisons: the 6 bytes of the mac (an exact heap block: the wrapper only forwards the pointer, so a
 * read or write of the bytes is a use-after-poison), the world's unrelated members, the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  run_all_tests compares the result with a reference
 * model of the CORRECT behaviour (see the construct file): getter used once, platform function called exactly once (or never) with the unchanged arguments and the same mac pointer, mac bytes unchanged,
 * guard slab unchanged.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "hwr_wnb.h"
#include <sanitizer/asan_interface.h>

static char why[240];
static unsigned char *mac;

static void poison(int on, const hwr_wnb_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	if (mac) fn(mac, 6);
	fn(hwr_wnb_world.unrelated, sizeof(hwr_wnb_world.unrelated));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
	(void)t;
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_set_neighbor_report(const hwr_wnb_case_t *t)
{
	poison(1, t);
	hwr_sg_wifi_hal_set_neighbor_report(t->ap_index, t->add, mac);
	poison(0, t);
}

static int check(const hwr_wnb_case_t *t, const unsigned char *mac_copy)
{
	const hwr_wnb_world_t *w = &hwr_wnb_world;
	int want_calls = t->no_fn ? 0 : 1;

	if (w->getter_calls != 1) { snprintf(why, sizeof(why), "getter used %d times, expected 1", w->getter_calls); return 0; }
	if (w->calls != want_calls) { snprintf(why, sizeof(why), "platform function called %d times, expected %d", w->calls, want_calls); return 0; }
	if (want_calls) {
		if (w->call_ap != t->ap_index) { snprintf(why, sizeof(why), "apIndex %u forwarded, expected %u", w->call_ap, t->ap_index); return 0; }
		if (w->call_add != t->add) { snprintf(why, sizeof(why), "add %u forwarded, expected %u", w->call_add, t->add); return 0; }
		if (w->call_mac != mac) { snprintf(why, sizeof(why), "mac pointer not forwarded unchanged"); return 0; }
	}
	if (mac && memcmp(mac, mac_copy, 6) != 0) { snprintf(why, sizeof(why), "mac bytes modified"); return 0; }
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

static void setup(const hwr_wnb_case_t *t, unsigned char *mac_copy)
{
	memset(&hwr_wnb_world, 0, sizeof(hwr_wnb_world));
	hwr_wnb_world.no_fn = t->no_fn; hwr_wnb_world.fn_ret = t->fn_ret;
	mac = NULL;
	if (t->mac_mode != 0) {
		mac = (unsigned char *)malloc(6);
		if (t->mac_mode == 1) { unsigned char m[6] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01 }; memcpy(mac, m, 6); }
		else memset(mac, t->mac_mode == 2 ? 0xff : 0, 6);
		memcpy(mac_copy, mac, 6);
	}
}

extern "C" void run_all_tests_sg_wifi_hal_set_neighbor_report(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_set_neighbor_report_suite[i].test_name != NULL; i++) {
			hwr_wnb_case_t *test = &sg_wifi_hal_set_neighbor_report_suite[i];
			unsigned char mac_copy[6];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test, mac_copy);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_set_neighbor_report(test);

			int ok = check(test, mac_copy);
			free(mac); mac = NULL;
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_hal_set_neighbor_report: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
