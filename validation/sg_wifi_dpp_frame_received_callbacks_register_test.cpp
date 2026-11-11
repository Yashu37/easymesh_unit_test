/*
 * TEST RUNNER: sg_wifi_dpp_frame_received_callbacks_register_test
 *
 * test_sg_wifi_dpp_frame_received_callbacks_register() POISONS what the function must not touch, calls the handler and unpoisons (once per registration): the callbacks table members before and after
 * the five DPP slots (only those slots may be written), the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  run_all_tests compares the table with a reference model of the CORRECT
 * behaviour (see the construct file): the callback held per slot afterwards, neighbouring members unchanged, RETURN_OK, one accessor use per call, guard slab unchanged.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hwr_wdg.h"
#include <sanitizer/asan_interface.h>

static char why[240];
static INT rets[2];

static void *cb_of(int k) { return k == 1 ? (void *)hwr_wdg_cb_a : k == 2 ? (void *)hwr_wdg_cb_b : NULL; }
static int arg_for(const hwr_wdg_case_t *t, int n, int slot) { int v = t->arg[slot]; return n == 0 ? v : (v == 1 ? 2 : v == 2 ? 1 : 0); }

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	wifi_device_callbacks_t *c = &hwr_wdg_world.cbs;

	fn(c->before, sizeof(c->before)); fn(c->after, sizeof(c->after));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison (once per registration) */
static void test_sg_wifi_dpp_frame_received_callbacks_register(const hwr_wdg_case_t *t)
{
	for (int n = 0; n < t->calls; n++) {
		poison(1);
		rets[n] = hwr_sg_wifi_dpp_frame_received_callbacks_register(
			(wifi_dppAuthResponse_callback_t)cb_of(arg_for(t, n, 0)), (wifi_dppConfigRequest_callback_t)cb_of(arg_for(t, n, 1)),
			(wifi_dppConfigResult_callback_t)cb_of(arg_for(t, n, 2)), (wifi_dppReconfigAnnounce_callback_t)cb_of(arg_for(t, n, 3)),
			(wifi_dppReconfigAuthResponse_callback_t)cb_of(arg_for(t, n, 4)));
		poison(0);
	}
}

static int check(const hwr_wdg_case_t *t)
{
	const wifi_device_callbacks_t *c = &hwr_wdg_world.cbs;
	void *got[5] = { (void *)c->dpp_auth_rsp_callback, (void *)c->dpp_config_req_callback, (void *)c->dpp_config_result_callback, (void *)c->dpp_reconfig_announce_callback, (void *)c->dpp_reconfig_auth_rsp_callback };

	for (int n = 0; n < t->calls; n++)
		if (rets[n] != RETURN_OK) { snprintf(why, sizeof(why), "call %d returned %d, expected %d", n, rets[n], RETURN_OK); return 0; }
	for (int s = 0; s < 5; s++) {
		void *want = cb_of(arg_for(t, t->calls - 1, s));
		if (got[s] != want) { snprintf(why, sizeof(why), "slot %d holds %p, expected %p", s, got[s], want); return 0; }
	}
	if (c->before[0] != (void *)0x11 || c->before[1] != (void *)0x12 || c->after[0] != (void *)0x21 || c->after[1] != (void *)0x22) { snprintf(why, sizeof(why), "neighbouring table members modified"); return 0; }
	if (hwr_wdg_world.accessor_calls != t->calls) { snprintf(why, sizeof(why), "accessor ran %d times, expected %d", hwr_wdg_world.accessor_calls, t->calls); return 0; }
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

static void setup(const hwr_wdg_case_t *t)
{
	hwr_wdg_world_t *w = &hwr_wdg_world;

	memset(w, 0, sizeof(*w));
	w->cbs.before[0] = (void *)0x11; w->cbs.before[1] = (void *)0x12; w->cbs.after[0] = (void *)0x21; w->cbs.after[1] = (void *)0x22;
	w->cbs.dpp_auth_rsp_callback = (wifi_dppAuthResponse_callback_t)cb_of(t->old[0]);
	w->cbs.dpp_config_req_callback = (wifi_dppConfigRequest_callback_t)cb_of(t->old[1]);
	w->cbs.dpp_config_result_callback = (wifi_dppConfigResult_callback_t)cb_of(t->old[2]);
	w->cbs.dpp_reconfig_announce_callback = (wifi_dppReconfigAnnounce_callback_t)cb_of(t->old[3]);
	w->cbs.dpp_reconfig_auth_rsp_callback = (wifi_dppReconfigAuthResponse_callback_t)cb_of(t->old[4]);
}

extern "C" void run_all_tests_sg_wifi_dpp_frame_received_callbacks_register(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_dpp_frame_received_callbacks_register_suite[i].test_name != NULL; i++) {
			hwr_wdg_case_t *test = &sg_wifi_dpp_frame_received_callbacks_register_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_dpp_frame_received_callbacks_register(test);

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
	printf("\nwifi_dpp_frame_received_callbacks_register: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
