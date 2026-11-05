/*
 * TEST RUNNER: hal_ipc_RMBeaconReportEvent_test
 *
 * The runner owns, in slabs, everything the function touches and POISONS their tails during the call:
 *   hwr_desc_slab  : [sizeof(hal_ipc_processor_desc_t), end)        the descriptor get_processor_desc() hands out
 *   hwr_node_slab  : [sizeof(hal_ipc_node_t), end)                  the notification client node
 *   hwr_report_slab: [sizeof(wifi_BeaconReport_t), end)             the caller's beacon report
 *   hwr_size_slab  : [sizeof(UINT), end)                            *out_array_size
 *   hwr_token_slab : [sizeof(UCHAR), end)                           *out_DialogToken
 *   hwr_sent_slab  : [sizeof(desc) + sizeof(report), end)           what send() may deliver at most
 *   hwr_log_buf    : [HWR_LOG_USE, HWR_LOG_SZ)
 * The report is filled with a byte pattern so the delivered scratch buffer can be compared byte by byte.  After every
 * call the runner checks the result, the log, that no malloc'd buffer is left allocated (counting stubs; a leak is
 * freed by the runner) and the bytes the stubbed send() received (descriptor apIndex / out_array_size / out_DialogToken
 * / len, scratch buffer = report).  The function is NOT modified.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "hwr_rmb.h"
#include <sanitizer/asan_interface.h>

#define SLAB(n, sz) static unsigned char n[sz]
SLAB(hwr_desc_slab, sizeof(hal_ipc_processor_desc_t) + 128);
SLAB(hwr_node_slab, sizeof(hal_ipc_node_t) + 64);
SLAB(hwr_report_slab, sizeof(wifi_BeaconReport_t) + 64);
SLAB(hwr_size_slab, 64);
SLAB(hwr_token_slab, 64);
SLAB(hwr_sent_slab, HWR_RMB_SENT_CAP + 128);
#define SCRATCH_SZ (sizeof(wifi_BeaconReport_t))
#define SENT_MAX   (sizeof(hal_ipc_processor_desc_t) + SCRATCH_SZ)

static void poison_all(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_desc_slab[sizeof(hal_ipc_processor_desc_t)], sizeof(hwr_desc_slab) - sizeof(hal_ipc_processor_desc_t));
	fn(&hwr_node_slab[sizeof(hal_ipc_node_t)], sizeof(hwr_node_slab) - sizeof(hal_ipc_node_t));
	fn(&hwr_report_slab[sizeof(wifi_BeaconReport_t)], sizeof(hwr_report_slab) - sizeof(wifi_BeaconReport_t));
	fn(&hwr_size_slab[sizeof(UINT)], sizeof(hwr_size_slab) - sizeof(UINT));
	fn(&hwr_token_slab[sizeof(UCHAR)], sizeof(hwr_token_slab) - sizeof(UCHAR));
	fn(&hwr_sent_slab[SENT_MAX], sizeof(hwr_sent_slab) - SENT_MAX);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static char why[220];

static void build(const hwr_rmb_case_t *t)
{
	hal_ipc_processor_desc_t *d = (hal_ipc_processor_desc_t *)hwr_desc_slab;

	memset(hwr_desc_slab, 0, sizeof(hwr_desc_slab));
	memset(hwr_node_slab, 0, sizeof(hwr_node_slab));
	memset(hwr_sent_slab, 0, sizeof(hwr_sent_slab));
	memset(hwr_log_buf, 0, HWR_LOG_USE);
	for (size_t i = 0; i < sizeof(wifi_BeaconReport_t); i++) hwr_report_slab[i] = (unsigned char)(i * 7 + 3);
	memset(hwr_size_slab, 0, sizeof(hwr_size_slab)); memcpy(hwr_size_slab, &t->array_size, sizeof(UINT));
	memset(hwr_token_slab, 0, sizeof(hwr_token_slab)); hwr_token_slab[0] = (unsigned char)t->token;
	d->type = hal_ipc_rm_beacon_report_event;
	snprintf(d->name, sizeof(d->name), "RMB");   /* short, so the log lines fit the log slot */
	d->ipc_processor[processor_type_ipc_client_notification_input] = hwr_rmb_processor_fn;
	memset(&hwr_rmb_world, 0, sizeof(hwr_rmb_world));
	hwr_rmb_world.desc = d;
	hwr_rmb_world.node = (hal_ipc_node_t *)hwr_node_slab;
	hwr_rmb_world.sent = hwr_sent_slab;
	hwr_rmb_world.fail_at = t->fail_at;
	hwr_rmb_world.node_fail = t->node_fail;
}

/* checks everything after the call; 1 = ok */
static int check_result(const hwr_rmb_case_t *t, INT ret)
{
	int fine = 1;

	if (ret != t->expected_ret) {
		snprintf(why, sizeof(why), "returned %d, expected %d%s", ret, t->expected_ret, (ret == 0 && t->expected_ret != 0) ? " (the event was sent)" : "");
		fine = 0;
	}
	if (fine && t->check_log == 1 && !strstr(hwr_log_buf, "Client input processor failed")) { snprintf(why, sizeof(why), "log lacks 'Client input processor failed': '%.120s'", hwr_log_buf); fine = 0; }
	if (fine && t->check_log == 2 && !strstr(hwr_log_buf, "ipc  processor failed")) { snprintf(why, sizeof(why), "log lacks 'ipc  processor failed': '%.120s'", hwr_log_buf); fine = 0; }
	if (fine && t->check_log == 3 && !strstr(hwr_log_buf, "Failed to create notification client node")) { snprintf(why, sizeof(why), "log lacks the node failure line: '%.120s'", hwr_log_buf); fine = 0; }
	if (fine && t->check_log == 4 && !strstr(hwr_log_buf, "ap_index:")) { snprintf(why, sizeof(why), "log lacks the ap_index line: '%.120s'", hwr_log_buf); fine = 0; }
	if (hwr_rmb_world.live != 0) {
		if (fine) snprintf(why, sizeof(why), "%d buffer(s) of %zu bytes still allocated after the call (leak: rdk_hal_ipc_exec failed before it could free the scratch buffer, tracker #78)", hwr_rmb_world.live, hwr_rmb_world.live_bytes);
		for (int i = 0; i < hwr_rmb_world.live; i++) free(hwr_rmb_world.live_ptrs[i]);      /* the runner cleans up */
		hwr_rmb_world.live = 0;
		fine = 0;
	}
	if (!fine) return 0;

	size_t want_total = ret == 0 ? SENT_MAX : (t->fail_at == 7 ? sizeof(hal_ipc_processor_desc_t) : 0);
	if (hwr_rmb_world.sent_total != want_total) { snprintf(why, sizeof(why), "%zu bytes were sent, expected %zu", hwr_rmb_world.sent_total, want_total); return 0; }
	if (ret == 0) {
		hal_ipc_processor_desc_t *d = (hal_ipc_processor_desc_t *)hwr_sent_slab;
		unsigned char *scr = hwr_sent_slab + sizeof(hal_ipc_processor_desc_t);
		if (d->in.rm_beacon_report_event_data.apIndex != t->ap) { snprintf(why, sizeof(why), "sent apIndex %u, expected %u", d->in.rm_beacon_report_event_data.apIndex, t->ap); return 0; }
		if (d->in.rm_beacon_report_event_data.out_array_size != t->array_size) { snprintf(why, sizeof(why), "sent out_array_size %u, expected %u", d->in.rm_beacon_report_event_data.out_array_size, t->array_size); return 0; }
		if (d->in.rm_beacon_report_event_data.out_DialogToken != (unsigned char)t->token) { snprintf(why, sizeof(why), "sent out_DialogToken %u, expected %u", d->in.rm_beacon_report_event_data.out_DialogToken, t->token); return 0; }
		if (d->len != SENT_MAX || d->scratch_buf_size != SCRATCH_SZ) { snprintf(why, sizeof(why), "sent len/scratch size %u/%u inconsistent", d->len, d->scratch_buf_size); return 0; }
		if (memcmp(scr, hwr_report_slab, sizeof(wifi_BeaconReport_t))) { snprintf(why, sizeof(why), "sent scratch buffer differs from the beacon report"); return 0; }
	}
	return 1;
}

static int run_case(const hwr_rmb_case_t *t)
{
	INT ret = 0;

	why[0] = 0;
	for (int i = 0; i < t->calls; i++) {
		build(t);
		poison_all(1);
		ret = hwr_rmb_call(t->ap, t->null_struct ? NULL : (wifi_BeaconReport_t *)hwr_report_slab, t->null_size ? NULL : (UINT *)hwr_size_slab, t->null_token ? NULL : (UCHAR *)hwr_token_slab);
		poison_all(0);
		if (!check_result(t, ret)) { char tmp[220]; snprintf(tmp, sizeof(tmp), "call %d: %.200s", i, why); memcpy(why, tmp, sizeof(why)); return 0; }
	}
	return 1;
}

extern "C" void run_all_tests_hal_ipc_RMBeaconReportEvent(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; hal_ipc_RMBeaconReportEvent_suite[i].test_name != NULL; i++) {
		hwr_rmb_case_t *test = &hal_ipc_RMBeaconReportEvent_suite[i];

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
	printf("\nhal_ipc_RMBeaconReportEvent: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
