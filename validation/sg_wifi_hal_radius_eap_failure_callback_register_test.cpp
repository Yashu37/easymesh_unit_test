/*
 * TEST RUNNER: sg_wifi_hal_radius_eap_failure_callback_register_test
 *
 * test_sg_wifi_hal_radius_eap_failure_callback_register() POISONS what the function must not touch, calls the handler and unpoisons (once per registration): every radius_eap_cb[] slot except the one at
 * num_radius_eap_cbs (when it is a valid slot; all slots when the table is full / not available), the neighbouring members (before[], other_cb[], num_other_cbs), the guard slab and the log slot tail
 * [HWR_LOG_USE, HWR_LOG_SZ).  hwr_wre_table is a stand-alone global with an ASan redzone, so a write past radius_eap_cb[MAX_REGISTERED_CB_NUM - 1] would be reported.  run_all_tests compares the table with a
 * reference model of the CORRECT behaviour (see the construct file): stored callbacks, num_radius_eap_cbs, earlier slots kept, neighbours untouched, guard slab unchanged.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "hwr_wre.h"
#include <sanitizer/asan_interface.h>

static char why[240];

static wifi_radiusEapFailure_callback fn_for(const hwr_wre_case_t *t, int k)
{
	if (t->null_cb) return NULL;
	return (k % 2 == 0) ? (wifi_radiusEapFailure_callback)hwr_wre_cb_b : (wifi_radiusEapFailure_callback)hwr_wre_cb_a;
}

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	wifi_device_callbacks_t *c = &hwr_wre_table;
	unsigned n = c->num_radius_eap_cbs;
	int writable = !hwr_wre_no_table && n < MAX_REGISTERED_CB_NUM;

	for (unsigned i = 0; i < MAX_REGISTERED_CB_NUM; i++) if (!on || !writable || i != n) fn(&c->radius_eap_cb[i], sizeof(c->radius_eap_cb[i]));
	fn(c->before, sizeof(c->before));
	fn(c->other_cb, sizeof(c->other_cb)); fn(&c->num_other_cbs, sizeof(c->num_other_cbs));
	if (!writable) fn(&c->num_radius_eap_cbs, sizeof(c->num_radius_eap_cbs));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison (once per registration) */
static void test_sg_wifi_hal_radius_eap_failure_callback_register(const hwr_wre_case_t *t)
{
	for (int k = 0; k < t->calls; k++) {
		poison(1);
		hwr_sg_wifi_hal_radius_eap_failure_callback_register(fn_for(t, k));
		poison(0);
	}
}

static int check(const hwr_wre_case_t *t)
{
	const wifi_device_callbacks_t *c = &hwr_wre_table;
	unsigned want_n = t->start_n;
	wifi_radiusEapFailure_callback want[MAX_REGISTERED_CB_NUM];

	for (unsigned i = 0; i < MAX_REGISTERED_CB_NUM; i++) want[i] = i < t->start_n ? (wifi_radiusEapFailure_callback)hwr_wre_cb_a : NULL;
	for (int k = 0; k < t->calls; k++) if (!t->no_table && want_n < MAX_REGISTERED_CB_NUM) want[want_n++] = fn_for(t, k);

	if (c->num_radius_eap_cbs != want_n) { snprintf(why, sizeof(why), "num_radius_eap_cbs is %u, expected %u", c->num_radius_eap_cbs, want_n); return 0; }
	for (unsigned i = 0; i < MAX_REGISTERED_CB_NUM; i++) if (c->radius_eap_cb[i] != want[i]) { snprintf(why, sizeof(why), "radius_eap_cb[%u] wrong", i); return 0; }
	if (c->before[0] != (void *)0x11 || c->before[1] != (void *)0x12 || c->num_other_cbs != 0x77) { snprintf(why, sizeof(why), "neighbouring members modified"); return 0; }
	for (unsigned i = 0; i < MAX_REGISTERED_CB_NUM; i++) if (c->other_cb[i] != (void *)(0x30 + i)) { snprintf(why, sizeof(why), "other_cb[%u] modified", i); return 0; }
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

static void setup(const hwr_wre_case_t *t)
{
	memset(&hwr_wre_table, 0, sizeof(hwr_wre_table));
	hwr_wre_no_table = t->no_table;
	hwr_wre_table.before[0] = (void *)0x11; hwr_wre_table.before[1] = (void *)0x12; hwr_wre_table.num_other_cbs = 0x77;
	for (unsigned i = 0; i < MAX_REGISTERED_CB_NUM; i++) hwr_wre_table.other_cb[i] = (void *)(0x30 + i);
	hwr_wre_table.num_radius_eap_cbs = t->start_n;
	for (unsigned i = 0; i < MAX_REGISTERED_CB_NUM && i < t->start_n; i++) hwr_wre_table.radius_eap_cb[i] = (wifi_radiusEapFailure_callback)hwr_wre_cb_a;
}

extern "C" void run_all_tests_sg_wifi_hal_radius_eap_failure_callback_register(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_radius_eap_failure_callback_register_suite[i].test_name != NULL; i++) {
			hwr_wre_case_t *test = &sg_wifi_hal_radius_eap_failure_callback_register_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_radius_eap_failure_callback_register(test);

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
	printf("\nwifi_hal_radius_eap_failure_callback_register: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
