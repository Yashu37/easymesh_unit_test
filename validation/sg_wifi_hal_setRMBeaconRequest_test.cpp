/*
 * TEST RUNNER: sg_wifi_hal_setRMBeaconRequest_test
 *
 * test_sg_wifi_hal_setRMBeaconRequest() POISONS what the function must not touch, calls the handler and unpoisons: the interface slots other than the addressed one, the fields of in_req whose Present flag is
 * off (SSID, beacon reporting, reporting detail, wide-band channel, requested element IDs, channel report incl. the entries after its zero terminator, extended element IDs and vendor specific always), the
 * guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  in_req and *out_DialogToken are exact heap blocks.  run_all_tests compares the result with a reference model of the CORRECT behaviour (see the
 * construct file): return value, the request passed on (every field and optional argument), *out_DialogToken, the lock released, guard slab unchanged.  Rows with last = 1 break the original: they run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <limits.h>
#include "hwr_wrb.h"
#include <sanitizer/asan_interface.h>

static char why[240];
static int ret_val;
static wifi_BeaconRequest_t *req;
static UCHAR *out_tok;
static unsigned char peer[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
#define TOK_CANARY 0xC3

static int args_bad(const hwr_wrb_case_t *t) { return t->peer_null || t->req_null || t->out_null; }
static int valid_freq(unsigned oc, unsigned ch) { return oc != 0 && oc != 99 && ch != 0 && ch <= 233; }

struct model {
	int ret, sent; int ssid_len; int chrep_len;
	int c0_ptr, c1_ptr;
};
static model run_model(const hwr_wrb_case_t *t)
{
	model m = {};
	if (args_bad(t)) { m.ret = WIFI_HAL_INVALID_ARGUMENTS; return m; }
	if (t->apIndex >= HWR_WRB_MAXI || t->vap_sta) { m.ret = WIFI_HAL_ERROR; return m; }
	if (t->channel != 0 && t->channel != 255 && !valid_freq(t->opClass, t->channel)) { m.ret = WIFI_HAL_ERROR; return m; }
	if (t->mode > 2) { m.ret = WIFI_HAL_ERROR; return m; }
	if (t->ssid_kind >= 0) m.ssid_len = t->ssid_kind == 0 ? 3 : t->ssid_kind == 1 ? 31 : 0;
	if (t->chrep_n >= 0) {
		m.chrep_len = t->chrep_n > 64 ? 64 : t->chrep_n;
		if (m.chrep_len == 0 && t->channel == 255) { m.ret = WIFI_HAL_ERROR; return m; }
	}
	if (t->wide_present) {
		if (t->wide_bw > 3) { m.ret = WIFI_HAL_ERROR; return m; }
		m.c0_ptr = valid_freq(t->opClass, t->seg0); m.c1_ptr = valid_freq(t->opClass, t->seg1);
	}
	m.sent = 1;
	m.ret = t->send_ret < 0 ? WIFI_HAL_ERROR : WIFI_HAL_SUCCESS;
	return m;
}

static void poison(int on, const hwr_wrb_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	hwr_wrb_world_t *w = &hwr_wrb_world;

	for (int i = 0; i < HWR_WRB_MAXI; i++) if (args_bad(t) || i != (int)t->apIndex) fn(&w->ifs[i], sizeof(w->ifs[i]));
	if (req && !args_bad(t)) {
		if (!req->ssidPresent) fn(req->ssid, sizeof(req->ssid));
		if (!req->beaconReportingPresent) fn(&req->beaconReporting, sizeof(req->beaconReporting));
		if (!req->reportingRetailPresent) fn(&req->reportingDetail, sizeof(req->reportingDetail));
		if (!req->wideBandWidthChannelPresent) fn(&req->wideBandwidthChannel, sizeof(req->wideBandwidthChannel));
		if (!req->requestedElementIDSPresent) fn(&req->requestedElementIDS, sizeof(req->requestedElementIDS));
		fn(&req->extdRequestedElementIDS, sizeof(req->extdRequestedElementIDS));
		fn(&req->vendorSpecific, sizeof(req->vendorSpecific));
		if (!req->channelReportPresent) fn(&req->channelReport, sizeof(req->channelReport));
		else {
			unsigned n = 0;
			while (n < 64 && req->channelReport.channels[n]) n++;
			if (n < 63) fn(&req->channelReport.channels[n + 1], 63 - n);   /* entries after the zero terminator are never read */
		}
	}
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_setRMBeaconRequest(const hwr_wrb_case_t *t)
{
	poison(1, t);
	ret_val = hwr_sg_wifi_hal_setRMBeaconRequest(t->apIndex, t->peer_null ? NULL : peer, t->req_null ? NULL : req, t->out_null ? NULL : out_tok);
	poison(0, t);
}

static int check(const hwr_wrb_case_t *t)
{
	const hwr_wrb_world_t *w = &hwr_wrb_world;
	model m = run_model(t);

	if (ret_val != m.ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret_val, m.ret); return 0; }
	if (w->send_calls != m.sent) { snprintf(why, sizeof(why), "send ran %d times, expected %d", w->send_calls, m.sent); return 0; }
	if (pthread_mutex_trylock((pthread_mutex_t *)&w->hal.hapd_lock) != 0) { snprintf(why, sizeof(why), "hapd_lock still locked"); return 0; }
	pthread_mutex_unlock((pthread_mutex_t *)&w->hal.hapd_lock);
	if (m.sent) {
		if (!w->mutex_held_at_send) { snprintf(why, sizeof(why), "hapd_lock not held during the send"); return 0; }
		if (w->send_iface != &w->ifs[t->apIndex] || w->send_addr != peer) { snprintf(why, sizeof(why), "interface / peer wrong"); return 0; }
		if (w->send_nrep != 0x0102 || w->send_oc != t->opClass || w->send_ch != t->channel || w->send_rand != 0x0304 || w->send_dur != 0x0506 || w->send_mode != t->mode || w->send_req_mode != 0 || w->send_last != 0) { snprintf(why, sizeof(why), "scalar fields wrong"); return 0; }
		if (memcmp(w->send_bssid, "\x0a\x0b\x0c\x0d\x0e\x0f", 6) != 0) { snprintf(why, sizeof(why), "bssid wrong"); return 0; }
		if (w->ssid_null != (t->ssid_kind < 0)) { snprintf(why, sizeof(why), "ssid presence wrong"); return 0; }
		if (!w->ssid_null) {
			char want[33]; memset(want, 0, sizeof(want)); if (t->ssid_kind == 0) memcpy(want, "abc", 3); else memset(want, 'S', m.ssid_len);
			if ((int)w->ssid_len != m.ssid_len || memcmp(w->ssid_val, want, 32) != 0) { snprintf(why, sizeof(why), "ssid len %zu, expected %d / content wrong", w->ssid_len, m.ssid_len); return 0; }
		}
		if (w->cond_null != !t->rep_present || w->thr_null != !t->rep_present || (t->rep_present && (w->cond != 3 || w->thr != 9))) { snprintf(why, sizeof(why), "beacon reporting wrong"); return 0; }
		if (w->det_null != !t->det_present || (t->det_present && w->det != 2)) { snprintf(why, sizeof(why), "reporting detail wrong"); return 0; }
		if ((int)w->chrep_len != m.chrep_len || w->chrep_null != (m.chrep_len == 0)) { snprintf(why, sizeof(why), "channel report length %u, expected %d", w->chrep_len, m.chrep_len); return 0; }
		if (m.chrep_len && w->chrep_ptr != req->channelReport.channels) { snprintf(why, sizeof(why), "channel report pointer wrong"); return 0; }
		for (int k = 0; k < m.chrep_len; k++) if (w->chrep[k] != (u8)(k + 1)) { snprintf(why, sizeof(why), "channel report entry %d wrong", k); return 0; }
		if (t->elem_present ? (w->elem_null || w->elem_len != 8 || w->elem_ptr != req->requestedElementIDS.ids) : (!w->elem_null || w->elem_len != 0)) { snprintf(why, sizeof(why), "requested elements wrong"); return 0; }
		if (w->w_null != !t->wide_present || (t->wide_present && w->w != t->wide_bw)) { snprintf(why, sizeof(why), "wide-band width wrong"); return 0; }
		if (w->c0_null != !m.c0_ptr || (m.c0_ptr && w->c0 != t->seg0) || w->c1_null != !m.c1_ptr || (m.c1_ptr && w->c1 != t->seg1)) { snprintf(why, sizeof(why), "wide-band centre segments wrong"); return 0; }
	}
	if (!t->out_null) {
		UCHAR want = (m.ret == WIFI_HAL_SUCCESS) ? (UCHAR)t->send_ret : (UCHAR)TOK_CANARY;
		if (*out_tok != want) { snprintf(why, sizeof(why), "*out_DialogToken is %u, expected %u", *out_tok, want); return 0; }
	}
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

static void setup(const hwr_wrb_case_t *t)
{
	hwr_wrb_world_t *w = &hwr_wrb_world;

	memset(w, 0, sizeof(*w));
	pthread_mutex_init(&w->hal.hapd_lock, NULL);
	w->send_ret = t->send_ret;
	for (int i = 0; i < HWR_WRB_MAXI; i++) w->ifs[i].vap_info.vap_mode = (i == (int)t->apIndex && t->vap_sta) ? wifi_vap_mode_sta : wifi_vap_mode_ap;
	out_tok = (UCHAR *)malloc(1); *out_tok = TOK_CANARY;
	req = NULL;
	if (!t->req_null) {
		req = (wifi_BeaconRequest_t *)malloc(sizeof(wifi_BeaconRequest_t));
		memset(req, 0, sizeof(*req));
		req->numRepetitions = 0x0102; req->opClass = (UCHAR)t->opClass; req->channel = (UCHAR)t->channel; req->randomizationInterval = 0x0304; req->duration = 0x0506; req->mode = (UCHAR)t->mode;
		memcpy(req->bssid, "\x0a\x0b\x0c\x0d\x0e\x0f", 6);
		if (t->ssid_kind >= 0) {
			req->ssidPresent = 1;
			if (t->ssid_kind == 0) memcpy(req->ssid, "abc", 3);
			else if (t->ssid_kind == 1) memset(req->ssid, 'S', sizeof(req->ssid));
		}
		if (t->rep_present) { req->beaconReportingPresent = 1; req->beaconReporting.condition = 3; req->beaconReporting.threshold = 9; }
		if (t->det_present) { req->reportingRetailPresent = 1; req->reportingDetail = 2; }
		if (t->chrep_n >= 0) {
			req->channelReportPresent = 1; req->channelReport.opClass = 115;
			for (int k = 0; k < t->chrep_n && k < 64; k++) req->channelReport.channels[k] = (UCHAR)(k + 1);
		}
		if (t->elem_present) { req->requestedElementIDSPresent = 1; for (int k = 0; k < 8; k++) req->requestedElementIDS.ids[k] = (UCHAR)(k + 1); }
		if (t->wide_present) { req->wideBandWidthChannelPresent = 1; req->wideBandwidthChannel.bandwidth = (UCHAR)t->wide_bw; req->wideBandwidthChannel.centerSeg0 = (UCHAR)t->seg0; req->wideBandwidthChannel.centerSeg1 = (UCHAR)t->seg1; }
	}
}

extern "C" void run_all_tests_sg_wifi_hal_setRMBeaconRequest(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_setRMBeaconRequest_suite[i].test_name != NULL; i++) {
			hwr_wrb_case_t *test = &sg_wifi_hal_setRMBeaconRequest_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_setRMBeaconRequest(test);

			int ok = check(test);
			free(req); req = NULL; free(out_tok); out_tok = NULL;
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_hal_setRMBeaconRequest: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
