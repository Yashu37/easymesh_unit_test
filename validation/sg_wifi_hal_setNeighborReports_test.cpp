/*
 * TEST RUNNER: sg_wifi_hal_setNeighborReports_test
 *
 * test_sg_wifi_hal_setNeighborReports() POISONS what the function must not touch, calls the handler and unpoisons: the interface slots other than the addressed one, conf->radio_measurements[1..4] (only [0]
 * is read), the optional sub-element members of every report whose Present flag is off (all of them are poisoned per report: wide-band, TSF, country string, candidate preference, termination, bearing, HT / VHT
 * capabilities and operation, secondary channel offset, RM capabilities, vendor specific, measurement pilot), the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  The reports are an exact heap block
 * of numNeighborReports entries and the wpabuf of the stub is an exact-size heap block, so an element longer than its buffer is a heap-buffer-overflow.  run_all_tests compares the result with a reference
 * model of the CORRECT behaviour (see the construct file): return value, database clears, every installed entry (BSSID, SSID, element bytes), buffer leaks, the lock released, guard slab unchanged.
 * Rows with last = 1 break the original: they run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <vector>
#include "hwr_wnr.h"
#include <sanitizer/asan_interface.h>

static char why[240];
static int ret_val;
static wifi_NeighborReport_t *reps;

static int arg_bad(const hwr_wnr_case_t *t) { return t->nrep_null || t->num < 1; }
static int iface_bad(const hwr_wnr_case_t *t) { return t->apIndex >= HWR_WNR_MAXI || t->vap_sta; }
static void put(std::vector<unsigned char> &v, unsigned long long x, int n) { for (int k = 0; k < n; k++) v.push_back((unsigned char)(x >> (8 * k))); }

static std::vector<unsigned char> model_nr(const hwr_wnr_case_t *t, unsigned i)
{
	std::vector<unsigned char> v;
	for (int k = 0; k < 6; k++) v.push_back((unsigned char)(k == 0 ? i + 1 : k + 1));
	put(v, 0x01020304u + i, 4); v.push_back(81); v.push_back((unsigned char)(i + 1)); v.push_back(7);
	if (t->flags & F_WIDE) { v.push_back(6); v.push_back(3); v.push_back(1); v.push_back(42); v.push_back(58); }
	if (t->flags & F_TSF) { v.push_back(1); v.push_back(4); put(v, 0x1111, 2); put(v, 0x2222, 2); }
	if (t->flags & F_CC) { v.push_back(2); v.push_back(2); v.push_back('U'); v.push_back('S'); }
	if (t->flags & F_PREF) { v.push_back(3); v.push_back(1); v.push_back(9); }
	if (t->flags & F_TERM) { v.push_back(4); v.push_back(10); put(v, 0x0102030405060708ULL, 8); put(v, 0x0a0b, 2); }
	if (t->flags & F_BEAR) { v.push_back(5); v.push_back(8); put(v, 0x1234, 2); put(v, 0x01020304, 4); put(v, 0x0506, 2); }
	if (t->flags & F_HTC) {
		wifi_HTCapabilities_t h; v.push_back(45); v.push_back(26); put(v, 0x1112, 2); v.push_back(3);
		for (size_t k = 0; k < sizeof(h.mcs); k++) v.push_back((unsigned char)k);
		put(v, 0x2122, 2); put(v, 0x01020304, 4); v.push_back(5);
	}
	if (t->flags & F_HTO) {
		wifi_HTOperation_t h; v.push_back(61); v.push_back(22); v.push_back(7);
		for (size_t k = 0; k < sizeof(h.opInfo); k++) v.push_back((unsigned char)(0x10 + k));
		for (size_t k = 0; k < sizeof(h.mcs); k++) v.push_back((unsigned char)(0x20 + k));
	}
	if (t->flags & F_VHTC) { v.push_back(191); v.push_back(12); put(v, 0x0a0b0c0d, 4); put(v, 0x1111, 2); put(v, 0x2222, 2); put(v, 0x3333, 2); put(v, 0x4444, 2); }
	if (t->flags & F_VHTO) { v.push_back(192); v.push_back(5); v.push_back(1); v.push_back(42); v.push_back(58); put(v, 0x5555, 2); }
	if (t->flags & F_SEC) { v.push_back(62); v.push_back(1); v.push_back(1); }
	if (t->flags & F_RM) {
		wifi_RMEnabledCapabilities_t h; v.push_back(70); v.push_back(5);
		for (size_t k = 0; k < sizeof(h.capabilities); k++) v.push_back((unsigned char)(0x30 + k));
	}
	if (t->flags & F_VEND) {
		wifi_VendorSpecific_t h; v.push_back(221); v.push_back(5 + 32);
		for (size_t k = 0; k < sizeof(h.oui); k++) v.push_back((unsigned char)(0x40 + k));
		for (size_t k = 0; k < sizeof(h.buff); k++) v.push_back((unsigned char)(0x50 + k));
	}
	if (t->flags & F_PILOT) {
		wifi_VendorSpecific_t h; v.push_back(66); v.push_back(3); v.push_back(221); v.push_back(5 + 32);
		for (size_t k = 0; k < sizeof(h.oui); k++) v.push_back((unsigned char)(0x60 + k));
		for (size_t k = 0; k < sizeof(h.buff); k++) v.push_back((unsigned char)(0x70 + k));
	}
	return v;
}

static void poison(int on, const hwr_wnr_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	hwr_wnr_world_t *w = &hwr_wnr_world;

	for (int i = 0; i < HWR_WNR_MAXI; i++) if (arg_bad(t) || i != (int)t->apIndex) fn(&w->ifs[i], sizeof(w->ifs[i]));
	if (!t->conf_null) fn(&w->conf.radio_measurements[1], 4);
	if (reps && !arg_bad(t)) {
		for (unsigned i = 0; i < t->num; i++) {
			wifi_NeighborReport_t *r = &reps[i];
			if (!(t->flags & F_WIDE)) fn(&r->wideBandwidthChannel, sizeof(r->wideBandwidthChannel));
			if (!(t->flags & F_TSF)) fn(&r->tsfInfo, sizeof(r->tsfInfo));
			if (!(t->flags & F_CC)) fn(&r->condensedCountryStr, sizeof(r->condensedCountryStr));
			if (!(t->flags & F_PREF)) fn(&r->bssTransitionCandidatePreference, sizeof(r->bssTransitionCandidatePreference));
			if (!(t->flags & F_TERM)) fn(&r->btmTerminationDuration, sizeof(r->btmTerminationDuration));
			if (!(t->flags & F_BEAR)) fn(&r->bearing, sizeof(r->bearing));
			if (!(t->flags & F_HTC)) fn(&r->htCaps, sizeof(r->htCaps));
			if (!(t->flags & F_HTO)) fn(&r->htOp, sizeof(r->htOp));
			if (!(t->flags & F_VHTC)) fn(&r->vbhtCaps, sizeof(r->vbhtCaps));
			if (!(t->flags & F_VHTO)) fn(&r->vhtOp, sizeof(r->vhtOp));
			if (!(t->flags & F_SEC)) fn(&r->secondaryChannelOffset, sizeof(r->secondaryChannelOffset));
			if (!(t->flags & F_RM)) fn(&r->rmEnabledCaps, sizeof(r->rmEnabledCaps));
			if (!(t->flags & F_VEND)) fn(&r->vendorSpecific, sizeof(r->vendorSpecific));
			if (!(t->flags & F_PILOT)) fn(&r->msmtPilotTransmission, sizeof(r->msmtPilotTransmission));
		}
	}
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_setNeighborReports(const hwr_wnr_case_t *t)
{
	poison(1, t);
	ret_val = hwr_sg_wifi_hal_setNeighborReports(t->apIndex, t->num, t->nrep_null ? NULL : reps);
	poison(0, t);
}

static int check(const hwr_wnr_case_t *t)
{
	const hwr_wnr_world_t *w = &hwr_wnr_world;
	int want;
	int want_free = 0, want_sets = 0;

	if (arg_bad(t)) want = WIFI_HAL_INVALID_ARGUMENTS;
	else if (t->apIndex >= HWR_WNR_MAXI || t->vap_sta || t->conf_null) want = WIFI_HAL_ERROR;
	else {
		want_free = 1;
		if (!t->rm_enable) want = WIFI_HAL_ERROR;
		else {
			want = WIFI_HAL_SUCCESS;
			for (unsigned i = 0; i < t->num; i++) {
				if (t->alloc_fail_at == (int)i + 1) { want = WIFI_HAL_ERROR; want_free = 2; break; }
				want_sets++;
				if (t->set_fail_at == (int)i + 1) { want = WIFI_HAL_ERROR; want_free = 2; break; }
			}
		}
	}
	if (ret_val != want) { snprintf(why, sizeof(why), "returned %d, expected %d", ret_val, want); return 0; }
	if (w->free_calls != want_free) { snprintf(why, sizeof(why), "database cleared %d times, expected %d", w->free_calls, want_free); return 0; }
	if (w->set_calls != want_sets) { snprintf(why, sizeof(why), "hostapd_neighbor_set ran %d times, expected %d", w->set_calls, want_sets); return 0; }
	if (w->live_bufs != 0) { snprintf(why, sizeof(why), "buffer leak (%d)", w->live_bufs); return 0; }
	if (want_sets && !w->mutex_held_at_set) { snprintf(why, sizeof(why), "hapd_lock not held during the set"); return 0; }
	for (int k = 0; k < want_sets && k < HWR_WNR_MAXSET; k++) {
		std::vector<unsigned char> nr = model_nr(t, (unsigned)k);
		unsigned char bssid[6] = { (unsigned char)(k + 1), 2, 3, 4, 5, 6 };
		char ssid[33]; size_t sl;
		memset(ssid, 0, sizeof(ssid));
		if (t->ssid_kind == 0) { memcpy(ssid, "ssid", 4); sl = 4; } else if (t->ssid_kind == 1) { memset(ssid, 'S', 31); sl = 31; } else sl = 0;
		if (memcmp(w->set_bssid[k], bssid, 6) != 0) { snprintf(why, sizeof(why), "entry %d: BSSID wrong", k); return 0; }
		if (w->set_ssid_len[k] != sl || memcmp(w->set_ssid[k], ssid, sl) != 0) { snprintf(why, sizeof(why), "entry %d: SSID wrong (len %zu, expected %zu)", k, w->set_ssid_len[k], sl); return 0; }
		if (w->set_nr_len[k] != nr.size() || (nr.size() <= HWR_WNR_NRCAP && memcmp(w->set_nr[k], nr.data(), nr.size()) != 0)) { snprintf(why, sizeof(why), "entry %d: element length %zu, expected %zu / bytes wrong", k, w->set_nr_len[k], nr.size()); return 0; }
	}
	{
		pthread_mutex_t *m = (pthread_mutex_t *)&w->hal.hapd_lock;
		if (pthread_mutex_trylock(m) != 0) { snprintf(why, sizeof(why), "hapd_lock still locked"); return 0; }
		pthread_mutex_unlock(m);
	}
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

static void setup(const hwr_wnr_case_t *t)
{
	hwr_wnr_world_t *w = &hwr_wnr_world;

	memset(w, 0, sizeof(*w));
	pthread_mutex_init(&w->hal.hapd_lock, NULL);
	w->set_fail_at = t->set_fail_at; w->alloc_fail_at = t->alloc_fail_at;
	snprintf(w->conf.iface, sizeof(w->conf.iface), "wlan%u", t->apIndex);
	w->conf.radio_measurements[0] = t->rm_enable ? 0x02 : 0x00;
	for (int k = 1; k < 5; k++) w->conf.radio_measurements[k] = (u8)(0xA0 + k);
	for (int i = 0; i < HWR_WNR_MAXI; i++) {
		w->ifs[i].vap_info.vap_mode = (i == (int)t->apIndex && t->vap_sta) ? wifi_vap_mode_sta : wifi_vap_mode_ap;
		w->ifs[i].u.ap.hapd.conf = t->conf_null ? NULL : &w->conf;
	}
	reps = NULL;
	if (!t->nrep_null) {
		unsigned n = t->num ? t->num : 1;
		reps = (wifi_NeighborReport_t *)malloc(n * sizeof(wifi_NeighborReport_t));
		memset(reps, 0, n * sizeof(wifi_NeighborReport_t));
		for (unsigned i = 0; i < n; i++) {
			wifi_NeighborReport_t *r = &reps[i];
			unsigned char b[6] = { (unsigned char)(i + 1), 2, 3, 4, 5, 6 };
			memcpy(r->bssid, b, 6); r->info = 0x01020304u + i; r->opClass = 81; r->channel = (UCHAR)(i + 1); r->phyTable = 7;
			if (t->ssid_kind == 0) memcpy(r->target_ssid, "ssid", 4); else if (t->ssid_kind == 1) memset(r->target_ssid, 'S', sizeof(r->target_ssid));
			if (t->flags & F_WIDE) { r->wideBandWidthChannelPresent = 1; r->wideBandwidthChannel.bandwidth = 1; r->wideBandwidthChannel.centerSeg0 = 42; r->wideBandwidthChannel.centerSeg1 = 58; }
			if (t->flags & F_TSF) { r->tsfPresent = 1; r->tsfInfo.offset = 0x1111; r->tsfInfo.interval = 0x2222; }
			if (t->flags & F_CC) { r->condensedCountrySringPresent = 1; r->condensedCountryStr.condensedStr[0] = 'U'; r->condensedCountryStr.condensedStr[1] = 'S'; }
			if (t->flags & F_PREF) { r->bssTransitionCandidatePreferencePresent = 1; r->bssTransitionCandidatePreference.preference = 9; }
			if (t->flags & F_TERM) { r->btmTerminationDurationPresent = 1; r->btmTerminationDuration.tsf = 0x0102030405060708ULL; r->btmTerminationDuration.duration = 0x0a0b; }
			if (t->flags & F_BEAR) { r->bearingPresent = 1; r->bearing.bearing = 0x1234; r->bearing.dist = 0x01020304; r->bearing.height = 0x0506; }
			if (t->flags & F_HTC) { r->htCapsPresent = 1; r->htCaps.info = 0x1112; r->htCaps.ampduParams = 3; for (size_t k = 0; k < sizeof(r->htCaps.mcs); k++) r->htCaps.mcs[k] = (UCHAR)k; r->htCaps.extended = 0x2122; r->htCaps.txBeamCaps = 0x01020304; r->htCaps.aselCaps = 5; }
			if (t->flags & F_HTO) { r->htOpPresent = 1; r->htOp.primary = 7; for (size_t k = 0; k < sizeof(r->htOp.opInfo); k++) r->htOp.opInfo[k] = (UCHAR)(0x10 + k); for (size_t k = 0; k < sizeof(r->htOp.mcs); k++) r->htOp.mcs[k] = (UCHAR)(0x20 + k); }
			if (t->flags & F_VHTC) { r->vhtCapsPresent = 1; r->vbhtCaps.info = 0x0a0b0c0d; r->vbhtCaps.mcs = 0x1111; r->vbhtCaps.rxHighestSupportedRate = 0x2222; r->vbhtCaps.txVHTmcs = 0x3333; r->vbhtCaps.txHighestSupportedRate = 0x4444; }
			if (t->flags & F_VHTO) { r->vhtOpPresent = 1; r->vhtOp.opInfo.bandwidth = 1; r->vhtOp.opInfo.centerSeg0 = 42; r->vhtOp.opInfo.centerSeg1 = 58; r->vhtOp.mcs_nss = 0x5555; }
			if (t->flags & F_SEC) { r->secondaryChannelOffsetPresent = 1; r->secondaryChannelOffset.secondaryChOffset = 1; }
			if (t->flags & F_RM) { r->rmEnabledCapsPresent = 1; for (size_t k = 0; k < sizeof(r->rmEnabledCaps.capabilities); k++) r->rmEnabledCaps.capabilities[k] = (UCHAR)(0x30 + k); }
			if (t->flags & F_VEND) { r->vendorSpecificPresent = 1; for (size_t k = 0; k < sizeof(r->vendorSpecific.oui); k++) r->vendorSpecific.oui[k] = (UCHAR)(0x40 + k); for (size_t k = 0; k < sizeof(r->vendorSpecific.buff); k++) r->vendorSpecific.buff[k] = (UCHAR)(0x50 + k); }
			if (t->flags & F_PILOT) { r->msmtPilotTransmissionPresent = 1; r->msmtPilotTransmission.pilot = 3; for (size_t k = 0; k < sizeof(r->msmtPilotTransmission.vendorSpecific.oui); k++) r->msmtPilotTransmission.vendorSpecific.oui[k] = (UCHAR)(0x60 + k); for (size_t k = 0; k < sizeof(r->msmtPilotTransmission.vendorSpecific.buff); k++) r->msmtPilotTransmission.vendorSpecific.buff[k] = (UCHAR)(0x70 + k); }
		}
	}
}

extern "C" void run_all_tests_sg_wifi_hal_setNeighborReports(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_setNeighborReports_suite[i].test_name != NULL; i++) {
			hwr_wnr_case_t *test = &sg_wifi_hal_setNeighborReports_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_setNeighborReports(test);

			int ok = check(test);
			free(reps); reps = NULL;
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_hal_setNeighborReports: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
