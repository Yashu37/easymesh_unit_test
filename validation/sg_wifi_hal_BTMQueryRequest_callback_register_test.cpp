/*
 * TEST RUNNER: sg_wifi_hal_BTMQueryRequest_callback_register_test
 *
 * test_sg_wifi_hal_BTMQueryRequest_callback_register() POISONS what the function must not touch, calls the handler and unpoisons: every btm_callback[] slot except the one at apIndex (and all of them, with the
 * neighbours, when apIndex is out of range or the table is not available), the neighbouring members before[] / after[], the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  hwr_wbq_table is a
 * stand-alone global with an ASan redzone, so a write past btm_callback[MAX_AP_INDEX - 1] would be reported.  run_all_tests compares the result with a reference model of the CORRECT behaviour (see the
 * construct file): return value, both callbacks of the addressed slot, all other slots and neighbours unchanged, the accessor not used for an out-of-range index, guard slab unchanged.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "hwr_wbq.h"
#include <sanitizer/asan_interface.h>

static char why[240];
static INT ret_val;

static int in_range(const hwr_wbq_case_t *t) { return t->ap_index < MAX_AP_INDEX; }

static void poison(int on, const hwr_wbq_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	wifi_device_callbacks_t *c = &hwr_wbq_table;
	int writable = in_range(t) && !t->no_table;

	for (unsigned i = 0; i < MAX_AP_INDEX; i++) if (!writable || i != t->ap_index) fn(&c->btm_callback[i], sizeof(c->btm_callback[i]));
	fn(c->before, sizeof(c->before)); fn(c->after, sizeof(c->after));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_BTMQueryRequest_callback_register(const hwr_wbq_case_t *t)
{
	poison(1, t);
	ret_val = hwr_sg_wifi_hal_BTMQueryRequest_callback_register(t->ap_index, (wifi_BTMQueryRequest_callback)hwr_wbq_q(t->new_q), (wifi_BTMResponse_callback)hwr_wbq_r(t->new_r));
	poison(0, t);
}

static int check(const hwr_wbq_case_t *t)
{
	const wifi_device_callbacks_t *c = &hwr_wbq_table;
	int ok_call = in_range(t) && !t->no_table;
	INT want = ok_call ? RETURN_OK : RETURN_ERR;
	int accessor_want = in_range(t) ? 1 : 0;

	if (ret_val != want) { snprintf(why, sizeof(why), "returned %d, expected %d", ret_val, want); return 0; }
	for (unsigned i = 0; i < MAX_AP_INDEX; i++) {
		int wq, wr;
		if (i == t->ap_index) { wq = ok_call ? t->new_q : t->old_q; wr = ok_call ? t->new_r : t->old_r; } else { wq = 3; wr = 3; }
		if ((void *)c->btm_callback[i].query_callback != hwr_wbq_q(wq)) { snprintf(why, sizeof(why), "btm_callback[%u].query_callback wrong", i); return 0; }
		if ((void *)c->btm_callback[i].response_callback != hwr_wbq_r(wr)) { snprintf(why, sizeof(why), "btm_callback[%u].response_callback wrong", i); return 0; }
	}
	if (c->before[0] != (void *)0x11 || c->before[1] != (void *)0x12 || c->after[0] != (void *)0x21 || c->after[1] != (void *)0x22) { snprintf(why, sizeof(why), "neighbouring members modified"); return 0; }
	if (hwr_wbq_accessor_calls != accessor_want) { snprintf(why, sizeof(why), "accessor ran %d times, expected %d", hwr_wbq_accessor_calls, accessor_want); return 0; }
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

static void setup(const hwr_wbq_case_t *t)
{
	memset(&hwr_wbq_table, 0, sizeof(hwr_wbq_table));
	hwr_wbq_no_table = t->no_table; hwr_wbq_accessor_calls = 0;
	hwr_wbq_table.before[0] = (void *)0x11; hwr_wbq_table.before[1] = (void *)0x12; hwr_wbq_table.after[0] = (void *)0x21; hwr_wbq_table.after[1] = (void *)0x22;
	for (unsigned i = 0; i < MAX_AP_INDEX; i++) {
		int q = (i == t->ap_index) ? t->old_q : 3, r = (i == t->ap_index) ? t->old_r : 3;
		hwr_wbq_table.btm_callback[i].query_callback = (wifi_BTMQueryRequest_callback)hwr_wbq_q(q);
		hwr_wbq_table.btm_callback[i].response_callback = (wifi_BTMResponse_callback)hwr_wbq_r(r);
	}
}

extern "C" void run_all_tests_sg_wifi_hal_BTMQueryRequest_callback_register(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_BTMQueryRequest_callback_register_suite[i].test_name != NULL; i++) {
			hwr_wbq_case_t *test = &sg_wifi_hal_BTMQueryRequest_callback_register_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_BTMQueryRequest_callback_register(test);

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
	printf("\nwifi_hal_BTMQueryRequest_callback_register: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
