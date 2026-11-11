/*
 * TEST RUNNER: sg_wifi_hal_getRadioTemperature_test
 *
 * test_sg_wifi_hal_getRadioTemperature() POISONS what the function must not touch, calls the handler and unpoisons: the world's unrelated members, the guard slab and the log slot tail
 * [HWR_LOG_USE, HWR_LOG_SZ).  The output is an exact 4-byte heap block, so an access beyond radio_Temperature is a heap-buffer-overflow; the function may only READ it after a successful platform call.
 * run_all_tests compares the result with a reference model of the CORRECT behaviour (see the construct file): return value, whether the platform is called for a NULL output is not prescribed (only the result is),
 * platform called with the unchanged index and pointer, output exactly as the platform left it, guard slab unchanged.  Rows with last = 1 break the original: they run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "hwr_wrt.h"
#include <sanitizer/asan_interface.h>

static char why[240];
static INT ret_val;
static wifi_radioTemperature_t *out;

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(hwr_wrt_world.unrelated, sizeof(hwr_wrt_world.unrelated));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_getRadioTemperature(const hwr_wrt_case_t *t)
{
	poison(1);
	ret_val = hwr_sg_wifi_hal_getRadioTemperature(t->radio_index, t->out_null ? NULL : out);
	poison(0);
}

static int check(const hwr_wrt_case_t *t)
{
	const hwr_wrt_world_t *w = &hwr_wrt_world;
	INT want;
	int want_calls;

	if (t->out_null) { want = RETURN_ERR; want_calls = 0; }
	else if (t->no_fn) { want = RETURN_ERR; want_calls = 0; }
	else { want_calls = 1; want = (t->fn_ret < 0) ? RETURN_ERR : RETURN_OK; }

	if (ret_val != want) { snprintf(why, sizeof(why), "returned %d, expected %d", ret_val, want); return 0; }
	if (!t->out_null && w->calls != want_calls) { snprintf(why, sizeof(why), "platform function called %d times, expected %d", w->calls, want_calls); return 0; }
	if (want_calls && !t->out_null) {
		if (w->call_index != t->radio_index) { snprintf(why, sizeof(why), "radioIndex %u forwarded, expected %u", w->call_index, t->radio_index); return 0; }
		if (w->call_out != out) { snprintf(why, sizeof(why), "output pointer not forwarded unchanged"); return 0; }
	}
	if (!t->out_null) {
		unsigned want_val = (!t->no_fn && t->write_temp) ? t->temp_value : 0xABABABABu;
		if (out->radio_Temperature != want_val) { snprintf(why, sizeof(why), "output is %u, expected %u", out->radio_Temperature, want_val); return 0; }
	}
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

static void setup(const hwr_wrt_case_t *t)
{
	memset(&hwr_wrt_world, 0, sizeof(hwr_wrt_world));
	hwr_wrt_world.no_fn = t->no_fn; hwr_wrt_world.fn_ret = t->fn_ret; hwr_wrt_world.write_temp = t->write_temp; hwr_wrt_world.temp_value = t->temp_value;
	out = (wifi_radioTemperature_t *)malloc(sizeof(*out));
	memset(out, 0xAB, sizeof(*out));
}

extern "C" void run_all_tests_sg_wifi_hal_getRadioTemperature(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_getRadioTemperature_suite[i].test_name != NULL; i++) {
			hwr_wrt_case_t *test = &sg_wifi_hal_getRadioTemperature_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_getRadioTemperature(test);

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
	printf("\nwifi_hal_getRadioTemperature: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
