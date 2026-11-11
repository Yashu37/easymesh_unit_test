/*
 * TEST RUNNER: sg_wifi_getNASta_test
 *
 * test_sg_wifi_getNASta() POISONS what the function must not touch, calls the handler and unpoisons: the params block (the wrapper only forwards the pointer, so a read is a use-after-poison; the platform
 * stub does not read it), the world's unrelated members, the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  params and sta_info are exact heap blocks (sta_info may only be written by the
 * platform stub, which is why it is not poisoned).  run_all_tests compares the result with a reference model of the CORRECT behaviour (see the construct file): return value, platform called once or not
 * at all with the unchanged arguments, sta_info exactly as the platform left it, guard slab unchanged.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "hwr_wns.h"
#include <sanitizer/asan_interface.h>

static char why[240];
static INT ret_val;
static wifi_na_sta_req_params_t *params;
static wifi_na_sta_info_t *info;

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	if (params) fn(params, sizeof(*params));
	fn(hwr_wns_world.unrelated, sizeof(hwr_wns_world.unrelated));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_getNASta(const hwr_wns_case_t *t)
{
	poison(1);
	ret_val = hwr_sg_wifi_getNASta(t->ap_index, t->params_null ? NULL : params, t->info_null ? NULL : info);
	poison(0);
}

static int check(const hwr_wns_case_t *t)
{
	const hwr_wns_world_t *w = &hwr_wns_world;
	int ap_ok = (t->ap_index >= 0 && t->ap_index < MAX_VAP);
	INT want; int want_calls = 0;

	if (!ap_ok) want = WIFI_HAL_INVALID_ARGUMENTS;
	else if (t->params_null || t->info_null) want = WIFI_HAL_ERROR;
	else { want = t->fn_ret; want_calls = 1; }

	if (ret_val != want) { snprintf(why, sizeof(why), "returned %d, expected %d", ret_val, want); return 0; }
	if (w->calls != want_calls) { snprintf(why, sizeof(why), "platform called %d times, expected %d", w->calls, want_calls); return 0; }
	if (want_calls) {
		if (w->call_ap != t->ap_index) { snprintf(why, sizeof(why), "apIndex %d forwarded, expected %d", w->call_ap, t->ap_index); return 0; }
		if (w->call_params != params || w->call_info != info) { snprintf(why, sizeof(why), "pointers not forwarded unchanged"); return 0; }
	}
	{
		unsigned want_rcpi = (want_calls && t->write_info) ? 120u : 0xABABABABu;
		if (!t->info_null && info->rcpi != want_rcpi) { snprintf(why, sizeof(why), "sta_info->rcpi is %u, expected %u", info->rcpi, want_rcpi); return 0; }
	}
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

static void setup(const hwr_wns_case_t *t)
{
	memset(&hwr_wns_world, 0, sizeof(hwr_wns_world));
	hwr_wns_world.fn_ret = t->fn_ret; hwr_wns_world.write_info = t->write_info;
	params = (wifi_na_sta_req_params_t *)malloc(sizeof(*params)); memset(params, 0xCD, sizeof(*params));
	info = (wifi_na_sta_info_t *)malloc(sizeof(*info)); memset(info, 0xAB, sizeof(*info));
}

extern "C" void run_all_tests_sg_wifi_getNASta(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_getNASta_suite[i].test_name != NULL; i++) {
			hwr_wns_case_t *test = &sg_wifi_getNASta_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_getNASta(test);

			int ok = check(test);
			free(params); free(info); params = NULL; info = NULL;
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_getNASta: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
