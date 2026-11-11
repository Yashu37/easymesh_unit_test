/*
 * TEST RUNNER: sg_wifi_hal_get_RegDomain_test
 *
 * test_sg_wifi_hal_get_RegDomain() POISONS what the function must not touch, calls the handler and unpoisons: the world's unrelated members, the guard slab and the log slot tail
 * [HWR_LOG_USE, HWR_LOG_SZ).  The output is an exact 4-byte heap block that only the platform stub may write.  run_all_tests compares the result with a reference model of the CORRECT behaviour (see the
 * construct file): return value, getter used once, platform called exactly once (or never) with the unchanged index and pointer, output exactly as the platform left it, guard slab unchanged.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "hwr_wgr.h"
#include <sanitizer/asan_interface.h>

static char why[240];
static INT ret_val;
static UINT *out;

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(hwr_wgr_world.unrelated, sizeof(hwr_wgr_world.unrelated));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_get_RegDomain(const hwr_wgr_case_t *t)
{
	poison(1);
	ret_val = hwr_sg_wifi_hal_get_RegDomain(t->radio_index, t->out_null ? NULL : out);
	poison(0);
}

static int check(const hwr_wgr_case_t *t)
{
	const hwr_wgr_world_t *w = &hwr_wgr_world;
	INT want = t->no_fn ? RETURN_ERR : t->fn_ret;
	int want_calls = t->no_fn ? 0 : 1;

	if (ret_val != want) { snprintf(why, sizeof(why), "returned %d, expected %d", ret_val, want); return 0; }
	if (w->getter_calls != 1) { snprintf(why, sizeof(why), "getter used %d times, expected 1", w->getter_calls); return 0; }
	if (w->calls != want_calls) { snprintf(why, sizeof(why), "platform function called %d times, expected %d", w->calls, want_calls); return 0; }
	if (want_calls) {
		if (w->call_index != t->radio_index) { snprintf(why, sizeof(why), "radioIndex %u forwarded, expected %u", w->call_index, t->radio_index); return 0; }
		if (w->call_out != (t->out_null ? NULL : out)) { snprintf(why, sizeof(why), "output pointer not forwarded unchanged"); return 0; }
	}
	if (!t->out_null) {
		unsigned want_val = (!t->no_fn && t->write_dom) ? t->dom_value : 0xABABABABu;
		if (*out != want_val) { snprintf(why, sizeof(why), "output is 0x%x, expected 0x%x", *out, want_val); return 0; }
	}
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

static void setup(const hwr_wgr_case_t *t)
{
	memset(&hwr_wgr_world, 0, sizeof(hwr_wgr_world));
	hwr_wgr_world.no_fn = t->no_fn; hwr_wgr_world.fn_ret = t->fn_ret; hwr_wgr_world.write_dom = t->write_dom; hwr_wgr_world.dom_value = t->dom_value;
	out = (UINT *)malloc(sizeof(*out));
	memset(out, 0xAB, sizeof(*out));
}

extern "C" void run_all_tests_sg_wifi_hal_get_RegDomain(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_get_RegDomain_suite[i].test_name != NULL; i++) {
			hwr_wgr_case_t *test = &sg_wifi_hal_get_RegDomain_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_get_RegDomain(test);

			int ok = check(test);
			free(out); out = NULL;
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_hal_get_RegDomain: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
