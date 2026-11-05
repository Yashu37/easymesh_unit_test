/*
 * TEST RUNNER: hal_ipc_send_steering_event_test
 *
 * The runner owns, in slabs, everything the function touches and POISONS their tails during the call:
 *   hwr_desc_slab    : [sizeof(hal_ipc_processor_desc_t), end)        the descriptor get_processor_desc() hands out
 *   hwr_node_slab    : [sizeof(hal_ipc_node_t), end)                  the notification client node
 *   hwr_event_slab   : [sizeof(wifi_steering_event_t), end)           the caller's steering event
 *   hwr_sent_slab    : [sizeof(desc), end)                            what send() may deliver at most (no scratch buffer)
 *   hwr_log_buf      : [HWR_LOG_USE, HWR_LOG_SZ)
 * The event is filled with a byte pattern (type / apIndex / timestamp set per case) so the delivered copy can be compared
 * byte by byte.  The function returns void, so "sent" is derived from the bytes the stubbed send() received.  After every call
 * the runner checks that,the log, that no malloc'd buffer is left allocated (counting stubs) and the bytes the
 * stubbed send() received (descriptor apIndex / len / peer MAC / response).  The function is NOT modified.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "hwr_sse.h"
#include <sanitizer/asan_interface.h>

#define SLAB(n, sz) static unsigned char n[sz]
SLAB(hwr_desc_slab, sizeof(hal_ipc_processor_desc_t) + 128);
SLAB(hwr_node_slab, sizeof(hal_ipc_node_t) + 64);
SLAB(hwr_event_slab, sizeof(wifi_steering_event_t) + 64);
SLAB(hwr_sent_slab, HWR_SSE_SENT_CAP + 128);
#define SENT_MAX   (sizeof(hal_ipc_processor_desc_t))

static void poison_all(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_desc_slab[sizeof(hal_ipc_processor_desc_t)], sizeof(hwr_desc_slab) - sizeof(hal_ipc_processor_desc_t));
	fn(&hwr_node_slab[sizeof(hal_ipc_node_t)], sizeof(hwr_node_slab) - sizeof(hal_ipc_node_t));
	fn(&hwr_event_slab[sizeof(wifi_steering_event_t)], sizeof(hwr_event_slab) - sizeof(wifi_steering_event_t));
	fn(&hwr_sent_slab[SENT_MAX], sizeof(hwr_sent_slab) - SENT_MAX);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static char why[220];

static void build(const hwr_sse_case_t *t)
{
	hal_ipc_processor_desc_t *d = (hal_ipc_processor_desc_t *)hwr_desc_slab;

	memset(hwr_desc_slab, 0, sizeof(hwr_desc_slab));
	memset(hwr_node_slab, 0, sizeof(hwr_node_slab));
	memset(hwr_sent_slab, 0, sizeof(hwr_sent_slab));
	memset(hwr_log_buf, 0, HWR_LOG_USE);
	for (size_t i = 0; i < sizeof(wifi_steering_event_t); i++) hwr_event_slab[i] = (unsigned char)(i * 7 + 3);
	{ wifi_steering_event_t *e = (wifi_steering_event_t *)hwr_event_slab; e->type = (wifi_steering_eventType_t)t->ev_type; e->apIndex = t->ev_ap; e->timestamp_ms = t->ev_ts; }
	d->type = hal_ipc_desc_type_steering_event;
	snprintf(d->name, sizeof(d->name), "STE");   /* short, so the log lines fit the log slot */
	d->ipc_processor[processor_type_ipc_client_notification_input] = hwr_sse_processor_fn;
	memset(&hwr_sse_world, 0, sizeof(hwr_sse_world));
	hwr_sse_world.desc = d;
	hwr_sse_world.node = (hal_ipc_node_t *)hwr_node_slab;
	hwr_sse_world.sent = hwr_sent_slab;
	hwr_sse_world.fail_at = t->fail_at;
	hwr_sse_world.node_fail = t->node_fail;
}

/* checks everything after the call; 1 = ok */
static int check_result(const hwr_sse_case_t *t, INT ret)
{
	int fine = 1;

	if (ret != t->expected_ret) {
		snprintf(why, sizeof(why), "returned %d, expected %d%s", ret, t->expected_ret, (ret == 0 && t->expected_ret != 0) ? " (the event was sent)" : "");
		fine = 0;
	}
	if (fine && t->check_log == 1 && !strstr(hwr_log_buf, "Client input processor failed")) { snprintf(why, sizeof(why), "log lacks 'Client input processor failed': '%.120s'", hwr_log_buf); fine = 0; }
	if (fine && t->check_log == 2 && !strstr(hwr_log_buf, "ipc  processor failed")) { snprintf(why, sizeof(why), "log lacks 'ipc  processor failed': '%.120s'", hwr_log_buf); fine = 0; }
	if (fine && t->check_log == 3 && !strstr(hwr_log_buf, "Failed to create notification client node")) { snprintf(why, sizeof(why), "log lacks the node failure line: '%.120s'", hwr_log_buf); fine = 0; }
	if (fine && t->check_log == 4 && !strstr(hwr_log_buf, "Steering event for apindex")) { snprintf(why, sizeof(why), "log lacks the steering event line: '%.120s'", hwr_log_buf); fine = 0; }
	if (hwr_sse_world.live != 0) {
		if (fine) snprintf(why, sizeof(why), "%d buffer(s) of %zu bytes still allocated after the call", hwr_sse_world.live, hwr_sse_world.live_bytes);
		for (int i = 0; i < hwr_sse_world.live; i++) free(hwr_sse_world.live_ptrs[i]);      /* the runner cleans up */
		hwr_sse_world.live = 0;
		fine = 0;
	}
	if (!fine) return 0;

	size_t want_total = ret == 0 ? SENT_MAX : 0;
	if (hwr_sse_world.sent_total != want_total) { snprintf(why, sizeof(why), "%zu bytes were sent, expected %zu", hwr_sse_world.sent_total, want_total); return 0; }
	if (ret == 0) {
		hal_ipc_processor_desc_t *d = (hal_ipc_processor_desc_t *)hwr_sent_slab;
		if (d->in.steering_event_data.steering_group_index != t->group) { snprintf(why, sizeof(why), "sent steering_group_index %u, expected %u", d->in.steering_event_data.steering_group_index, t->group); return 0; }
		if (d->len != sizeof(hal_ipc_processor_desc_t) || d->scratch_buf_size != 0) { snprintf(why, sizeof(why), "sent len/scratch size %u/%u inconsistent (the server expects len == sizeof(desc) + scratch)", d->len, d->scratch_buf_size); return 0; }
		if (memcmp(&d->in.steering_event_data.evt, hwr_event_slab, sizeof(wifi_steering_event_t))) { snprintf(why, sizeof(why), "sent steering event differs from the caller's wifi_steering_event_t"); return 0; }
	}
	return 1;
}

static int run_case(const hwr_sse_case_t *t)
{
	INT ret = 0;

	why[0] = 0;
	for (int i = 0; i < t->calls; i++) {
		build(t);
		poison_all(1);
		hwr_sse_call(t->group, t->null_event ? NULL : (wifi_steering_event_t *)hwr_event_slab);
		poison_all(0);
		ret = hwr_sse_world.sent_total ? 0 : -1;                 /* void function: sent / not sent */
		if (!check_result(t, ret)) { char tmp[220]; snprintf(tmp, sizeof(tmp), "call %d: %.200s", i, why); memcpy(why, tmp, sizeof(why)); return 0; }
	}
	return 1;
}

extern "C" void run_all_tests_hal_ipc_send_steering_event(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; hal_ipc_send_steering_event_suite[i].test_name != NULL; i++) {
		hwr_sse_case_t *test = &hal_ipc_send_steering_event_suite[i];

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
	printf("\nhal_ipc_send_steering_event: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
