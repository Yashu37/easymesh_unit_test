/*
 * TEST RUNNER: hal_ipc_init_test
 *
 * The runner owns, in slabs, everything the function touches and POISONS their tails during the calls:
 *   hwr_cb_slab : [sizeof(hwr_hin_world_t), end)     the device callbacks structure the registration functions write
 *                                                    (steering callback, bcnrpt_callback[15], btm_callback[15]);
 *                                                    an index beyond MAX_AP_INDEX would hit the poison
 *   hwr_log_buf : [HWR_LOG_USE, HWR_LOG_SZ)
 * Foreign registrations are preset (distinct function pointers), the function is called init_calls times, and the
 * runner checks every return value, the registered callbacks afterwards (steering / bcnrpt_callback[] / btm_callback[]:
 * ours, or the foreign one that must not be overwritten), the nodes created (counts per type) and the log.  The
 * function is NOT modified.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "hwr_hin.h"
#include <sanitizer/asan_interface.h>

static unsigned char hwr_cb_slab[sizeof(hwr_hin_world_t) + 128];

static INT foreign_rm(UINT a, wifi_BeaconReport_t *s, UINT *n, UCHAR *t) { (void)a; (void)s; (void)n; (void)t; return 0; }
static void foreign_steer(UINT g, wifi_steering_event_t *e) { (void)g; (void)e; }
static INT foreign_btmq(UINT a, CHAR *m, wifi_BTMQuery_t *q, UINT s, wifi_BTMRequest_t *r) { (void)a; (void)m; (void)q; (void)s; (void)r; return 0; }
static INT foreign_btmr(UINT a, CHAR *m, wifi_BTMResponse_t *r) { (void)a; (void)m; (void)r; return 0; }

static void poison_all(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_cb_slab[sizeof(hwr_hin_world_t)], sizeof(hwr_cb_slab) - sizeof(hwr_hin_world_t));
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static char why[220];

static void build(const hwr_hin_case_t *t)
{
	hwr_hin_world_t *w = (hwr_hin_world_t *)hwr_cb_slab;

	memset(hwr_cb_slab, 0, sizeof(hwr_cb_slab));
	memset(hwr_log_buf, 0, HWR_LOG_USE);
	memset(&hwr_hin_rec, 0, sizeof(hwr_hin_rec));
	hwr_hin_rec.fail_mask = t->node_fail;
	for (int i = 0; i < HWR_HIN_MAX_AP; i++) {
		if (t->foreign_rm & (1u << i)) w->device_callbacks.bcnrpt_callback[i] = foreign_rm;
		if (t->foreign_btm) { w->device_callbacks.btm_callback[i].query_callback = foreign_btmq; w->device_callbacks.btm_callback[i].response_callback = foreign_btmr; }
	}
	if (t->foreign_steer) w->device_callbacks.steering_event_callback = foreign_steer;
	hwr_hin_world = w;
}

static int check_state(const hwr_hin_case_t *t)
{
	wifi_device_callbacks_t *c = &((hwr_hin_world_t *)hwr_cb_slab)->device_callbacks;

	if ((void *)c->steering_event_callback != hwr_hin_cb_steer()) { snprintf(why, sizeof(why), "steering callback not registered"); return 0; }
	for (int i = 0; i < HWR_HIN_MAX_AP; i++) {
		void *want_rm = (t->foreign_rm & (1u << i)) ? (void *)foreign_rm : hwr_hin_cb_rm();
		if ((void *)c->bcnrpt_callback[i] != want_rm) { snprintf(why, sizeof(why), "bcnrpt_callback[%d] is %s", i, (void *)c->bcnrpt_callback[i] == NULL ? "not registered" : "not the expected callback (a foreign registration was overwritten?)"); return 0; }
		if ((void *)c->btm_callback[i].query_callback != hwr_hin_cb_btmq() || (void *)c->btm_callback[i].response_callback != hwr_hin_cb_btmr()) { snprintf(why, sizeof(why), "btm_callback[%d] not registered", i); return 0; }
	}
	return 1;
}

static int run_case(const hwr_hin_case_t *t)
{
	why[0] = 0;
	build(t);
	poison_all(1);
	for (int i = 0; i < t->init_calls; i++) {
		int ret = hwr_hal_ipc_init();
		if (ret != t->expected_ret[i]) {
			poison_all(0);
			snprintf(why, sizeof(why), "call %d returned %d, expected %d%s", i, ret, t->expected_ret[i], (ret == 0 && t->expected_ret[i] != 0) ? " (a callback registration failed but hal_ipc_init reported success)" : "");
			return 0;
		}
	}
	poison_all(0);
	if (!check_state(t)) return 0;
	if (t->clients >= 0 && hwr_hin_rec.calls[hal_ipc_node_type_notification_client] != t->clients) { snprintf(why, sizeof(why), "notification client node created %d time(s), expected %d", hwr_hin_rec.calls[hal_ipc_node_type_notification_client], t->clients); return 0; }
	if (t->servers >= 0 && hwr_hin_rec.calls[hal_ipc_node_type_sync_call_server] != t->servers) { snprintf(why, sizeof(why), "sync-call server node (listener thread) created %d time(s), expected %d", hwr_hin_rec.calls[hal_ipc_node_type_sync_call_server], t->servers); return 0; }
	if (t->check_log == 1 && !strstr(hwr_log_buf, "RM beacon")) { snprintf(why, sizeof(why), "log lacks the RM beacon registration failure: '%.120s'", hwr_log_buf); return 0; }
	if (t->check_log == 2 && !strstr(hwr_log_buf, "Failed to create notification client node")) { snprintf(why, sizeof(why), "log lacks the client node failure: '%.120s'", hwr_log_buf); return 0; }
	if (t->check_log == 3 && !strstr(hwr_log_buf, "Failed to create sync call server node")) { snprintf(why, sizeof(why), "log lacks the sync call server failure: '%.120s'", hwr_log_buf); return 0; }
	return 1;
}

extern "C" void run_all_tests_hal_ipc_init(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; hal_ipc_init_suite[i].test_name != NULL; i++) {
		hwr_hin_case_t *test = &hal_ipc_init_suite[i];

		printf("--- Running Test: %s ---\n", test->test_name);

		int ret = run_case(test);

		if (ret == 1) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=1, got=%d) %s =====\n", test->test_name, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nhal_ipc_init: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
