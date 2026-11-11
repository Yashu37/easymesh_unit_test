/*
 * TEST RUNNER: sg_wifi_hal_staConnectionStatus_callback_register_test
 *
 * test_sg_wifi_hal_staConnectionStatus_callback_register() POISONS what the function must not touch, calls the handler and unpoisons (once per registration): the callbacks table members before and after
 * sta_conn_status_callback (only that slot may be written), the whole table when the accessor returns NULL, the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  run_all_tests compares the table with
 * a reference model of the CORRECT behaviour (see the construct file): the callback held afterwards, neighbouring members unchanged, guard slab unchanged.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hwr_wcs.h"
#include <sanitizer/asan_interface.h>

static char why[240];

static wifi_staConnectionStatus_callback cb_of(int k) { return k == 1 ? (wifi_staConnectionStatus_callback)hwr_wcs_cb_a : k == 2 ? (wifi_staConnectionStatus_callback)hwr_wcs_cb_b : NULL; }
static int cb_for_call(const hwr_wcs_case_t *t, int n) { return n == 0 ? t->new_cb : (t->new_cb == 1 ? 2 : 1); }

static void poison(int on, const hwr_wcs_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	wifi_device_callbacks_t *c = &hwr_wcs_world.cbs;

	if (t->no_cbs) fn(c, sizeof(*c));
	else { fn(c->before, sizeof(c->before)); fn(c->after, sizeof(c->after)); }
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison (once per registration) */
static void test_sg_wifi_hal_staConnectionStatus_callback_register(const hwr_wcs_case_t *t)
{
	for (int n = 0; n < t->calls; n++) {
		poison(1, t);
		hwr_sg_wifi_hal_staConnectionStatus_callback_register(cb_of(cb_for_call(t, n)));
		poison(0, t);
	}
}

static int check(const hwr_wcs_case_t *t)
{
	const wifi_device_callbacks_t *c = &hwr_wcs_world.cbs;
	wifi_staConnectionStatus_callback want = cb_of(t->old_cb);

	for (int n = 0; n < t->calls; n++) {
		if (!t->no_cbs) want = cb_of(cb_for_call(t, n));
	}
	if (c->sta_conn_status_callback != want) { snprintf(why, sizeof(why), "callback slot holds %p, expected %p", (void *)c->sta_conn_status_callback, (void *)want); return 0; }
	if (c->before[0] != (void *)0x11 || c->before[1] != (void *)0x12 || c->after[0] != (void *)0x21 || c->after[1] != (void *)0x22) { snprintf(why, sizeof(why), "neighbouring table members modified"); return 0; }
	if (hwr_wcs_world.accessor_calls != t->calls) { snprintf(why, sizeof(why), "accessor ran %d times, expected %d", hwr_wcs_world.accessor_calls, t->calls); return 0; }
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

static void setup(const hwr_wcs_case_t *t)
{
	hwr_wcs_world_t *w = &hwr_wcs_world;

	memset(w, 0, sizeof(*w));
	w->no_cbs = t->no_cbs;
	w->cbs.before[0] = (void *)0x11; w->cbs.before[1] = (void *)0x12; w->cbs.after[0] = (void *)0x21; w->cbs.after[1] = (void *)0x22;
	w->cbs.sta_conn_status_callback = cb_of(t->old_cb);
}

extern "C" void run_all_tests_sg_wifi_hal_staConnectionStatus_callback_register(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_staConnectionStatus_callback_register_suite[i].test_name != NULL; i++) {
			hwr_wcs_case_t *test = &sg_wifi_hal_staConnectionStatus_callback_register_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_staConnectionStatus_callback_register(test);

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
	printf("\nwifi_hal_staConnectionStatus_callback_register: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
