/*
 * TEST RUNNER: hal_ipc_BTMResponseEvent_test
 *
 * The runner owns, in slabs, everything the function touches and POISONS their tails during the call:
 *   hwr_desc_slab    : [sizeof(hal_ipc_processor_desc_t), end)        the descriptor get_processor_desc() hands out
 *   hwr_node_slab    : [sizeof(hal_ipc_node_t), end)                  the notification client node
 *   hwr_response_slab: [sizeof(wifi_BTMResponse_t), end)              the caller's response
 *   hwr_mac_slab     : [strlen(mac) + 1, end)                         the peer MAC string (an over-read aborts)
 *   hwr_sent_slab    : [sizeof(desc), end)                            what send() may deliver at most (no scratch buffer)
 *   hwr_log_buf      : [HWR_LOG_USE, HWR_LOG_SZ)
 * The response is filled with a byte pattern so the delivered copy can be compared byte by byte.  After every call
 * the runner checks the result, the log, that no malloc'd buffer is left allocated (counting stubs) and the bytes the
 * stubbed send() received (descriptor apIndex / len / peer MAC / response).  The function is NOT modified.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "hwr_bre.h"
#include <sanitizer/asan_interface.h>

#define SLAB(n, sz) static unsigned char n[sz]
SLAB(hwr_desc_slab, sizeof(hal_ipc_processor_desc_t) + 128);
SLAB(hwr_node_slab, sizeof(hal_ipc_node_t) + 64);
SLAB(hwr_response_slab, sizeof(wifi_BTMResponse_t) + 64);
SLAB(hwr_mac_slab, 64);
SLAB(hwr_sent_slab, HWR_BRE_SENT_CAP + 128);
#define SENT_MAX   (sizeof(hal_ipc_processor_desc_t))
static size_t mac_len;

static void poison_all(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_desc_slab[sizeof(hal_ipc_processor_desc_t)], sizeof(hwr_desc_slab) - sizeof(hal_ipc_processor_desc_t));
	fn(&hwr_node_slab[sizeof(hal_ipc_node_t)], sizeof(hwr_node_slab) - sizeof(hal_ipc_node_t));
	fn(&hwr_response_slab[sizeof(wifi_BTMResponse_t)], sizeof(hwr_response_slab) - sizeof(wifi_BTMResponse_t));
	fn(&hwr_mac_slab[mac_len + 1], sizeof(hwr_mac_slab) - (mac_len + 1));
	fn(&hwr_sent_slab[SENT_MAX], sizeof(hwr_sent_slab) - SENT_MAX);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static char why[220];

static void build(const hwr_bre_case_t *t)
{
	hal_ipc_processor_desc_t *d = (hal_ipc_processor_desc_t *)hwr_desc_slab;

	memset(hwr_desc_slab, 0, sizeof(hwr_desc_slab));
	memset(hwr_node_slab, 0, sizeof(hwr_node_slab));
	memset(hwr_sent_slab, 0, sizeof(hwr_sent_slab));
	memset(hwr_log_buf, 0, HWR_LOG_USE);
	for (size_t i = 0; i < sizeof(wifi_BTMResponse_t); i++) hwr_response_slab[i] = (unsigned char)(i * 7 + 3);
	memset(hwr_mac_slab, 0, sizeof(hwr_mac_slab));
	mac_len = t->mac ? strlen(t->mac) : 0;
	if (t->mac) memcpy(hwr_mac_slab, t->mac, mac_len + 1);
	d->type = hal_ipc_btm_response_event;
	snprintf(d->name, sizeof(d->name), "BTMR");   /* short, so the log lines fit the log slot */
	d->ipc_processor[processor_type_ipc_client_notification_input] = hwr_bre_processor_fn;
	memset(&hwr_bre_world, 0, sizeof(hwr_bre_world));
	hwr_bre_world.desc = d;
	hwr_bre_world.node = (hal_ipc_node_t *)hwr_node_slab;
	hwr_bre_world.sent = hwr_sent_slab;
	hwr_bre_world.fail_at = t->fail_at;
	hwr_bre_world.node_fail = t->node_fail;
}

static int hexv(char c) { return c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10; }

/* checks everything after the call; 1 = ok */
static int check_result(const hwr_bre_case_t *t, INT ret)
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
	if (fine && t->check_log == 5 && !strstr(hwr_log_buf, "invalid peer mac string")) { snprintf(why, sizeof(why), "log lacks the invalid peer mac line: '%.120s'", hwr_log_buf); fine = 0; }
	if (hwr_bre_world.live != 0) {
		if (fine) snprintf(why, sizeof(why), "%d buffer(s) of %zu bytes still allocated after the call", hwr_bre_world.live, hwr_bre_world.live_bytes);
		for (int i = 0; i < hwr_bre_world.live; i++) free(hwr_bre_world.live_ptrs[i]);      /* the runner cleans up */
		hwr_bre_world.live = 0;
		fine = 0;
	}
	if (!fine) return 0;

	size_t want_total = ret == 0 ? SENT_MAX : 0;
	if (hwr_bre_world.sent_total != want_total) { snprintf(why, sizeof(why), "%zu bytes were sent, expected %zu", hwr_bre_world.sent_total, want_total); return 0; }
	if (ret == 0) {
		hal_ipc_processor_desc_t *d = (hal_ipc_processor_desc_t *)hwr_sent_slab;
		if (d->in.btm_response_event_data.apIndex != t->ap) { snprintf(why, sizeof(why), "sent apIndex %u, expected %u", d->in.btm_response_event_data.apIndex, t->ap); return 0; }
		if (d->len != sizeof(hal_ipc_processor_desc_t) || d->scratch_buf_size != 0) { snprintf(why, sizeof(why), "sent len/scratch size %u/%u inconsistent (the server expects len == sizeof(desc) + scratch)", d->len, d->scratch_buf_size); return 0; }
		if (t->exp_mac) {
			unsigned char want[6];
			for (int k = 0; k < 6; k++) want[k] = (unsigned char)(hexv(t->exp_mac[2 * k]) * 16 + hexv(t->exp_mac[2 * k + 1]));
			if (memcmp(d->in.btm_response_event_data.peerMac, want, 6)) {
				unsigned char *g = (unsigned char *)d->in.btm_response_event_data.peerMac;
				snprintf(why, sizeof(why), "sent peer MAC %02x:%02x:%02x:%02x:%02x:%02x, expected %s (string \"%s\")", g[0], g[1], g[2], g[3], g[4], g[5], t->exp_mac, t->mac);
				return 0;
			}
		}
		if (memcmp(&d->in.btm_response_event_data.response, hwr_response_slab, sizeof(wifi_BTMResponse_t))) { snprintf(why, sizeof(why), "sent response differs from the caller's wifi_BTMResponse_t"); return 0; }
	}
	return 1;
}

static int run_case(const hwr_bre_case_t *t)
{
	INT ret = 0;

	why[0] = 0;
	for (int i = 0; i < t->calls; i++) {
		build(t);
		poison_all(1);
		ret = hwr_bre_call(t->ap, t->mac ? (CHAR *)hwr_mac_slab : NULL, t->null_response ? NULL : (wifi_BTMResponse_t *)hwr_response_slab);
		poison_all(0);
		if (!check_result(t, ret)) { char tmp[220]; snprintf(tmp, sizeof(tmp), "call %d: %.200s", i, why); memcpy(why, tmp, sizeof(why)); return 0; }
	}
	return 1;
}

extern "C" void run_all_tests_hal_ipc_BTMResponseEvent(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; hal_ipc_BTMResponseEvent_suite[i].test_name != NULL; i++) {
		hwr_bre_case_t *test = &hal_ipc_BTMResponseEvent_suite[i];

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
	printf("\nhal_ipc_BTMResponseEvent: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
