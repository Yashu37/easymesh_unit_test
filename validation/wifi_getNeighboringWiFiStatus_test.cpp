/*
 * TEST RUNNER: wifi_getNeighboringWiFiStatus_test
 *
 * Same shape as the other *_test.cpp runners: construct_wifi_getNeighboringWiFiStatus_input() builds the world for a row (radio, private interface, scan
 * state, scan result map, frequency filter), test_wifi_getNeighboringWiFiStatus() POISONS what the function must not touch, calls the handler and
 * unpoisons, then run_all_tests compares the return value and the side effects.
 *
 * The caller's two output slots live in runner slabs (a 8-byte pointer slot, a 4-byte size slot, prefilled with a stale 0xdeadbeef / 99); during the call
 * the slab bytes behind the slots, the unused tail of the result map [n, GNW_MAXB), the unused scan results of the store, the unused tail of the
 * frequency filter, the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ) are POISONED: a write past an output slot, a read of a result that
 * is not in the map or of a filter entry past num, or a log write past the slot aborts under ASan.  The returned array is a heap block: ASan also
 * guards its ends, and the runner frees it (a leak or double free aborts).
 * Checks: return value, outputs untouched on the early error paths / NULL,0 on a copy error, scan_state and result flags afterwards, errno EAGAIN when
 * not ready, the number of entries (results passing the filter) and every field of every returned neighbor_ap2 entry (SSID, BSSID, mode, channel,
 * security, encryption, band, standards, bandwidth, rates, beacon period, DTIM, noise, utilization, BSS load / station count).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "hwr_gnw.h"
#include <sanitizer/asan_interface.h>

static unsigned char ptr_slab[32], size_slab[16];
#define STALE_PTR ((wifi_neighbor_ap2_t *)(unsigned long)0xdeadbeefUL)
static char why[240];

static void poison(int on, const gnw_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&ptr_slab[sizeof(void *)], sizeof(ptr_slab) - sizeof(void *));
	fn(&size_slab[sizeof(unsigned)], sizeof(size_slab) - sizeof(unsigned));
	if (t->nbss < GNW_MAXB) {
		fn(&gnw_map1.items[t->nbss], (GNW_MAXB - t->nbss) * sizeof(gnw_map1.items[0]));
		fn(&gnw_store[t->nbss], (GNW_MAXB - t->nbss) * sizeof(gnw_store[0]));
	}
	if (t->nfilt < 8) fn(&gnw_filt_slab[t->nfilt], (8 - t->nfilt) * sizeof(unsigned int));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static wifi_neighbor_ap2_t **ap_slot(void) { return (wifi_neighbor_ap2_t **)ptr_slab; }
static unsigned int *sz_slot(void) { return (unsigned int *)size_slab; }

static void prefill(void)
{
	memset(ptr_slab, 0x5A, sizeof(ptr_slab)); memset(size_slab, 0x5A, sizeof(size_slab));
	*ap_slot() = STALE_PTR; *sz_slot() = 99;
}

/* poison, call, unpoison -- returns what wifi_getNeighboringWiFiStatus returned */
int test_wifi_getNeighboringWiFiStatus(const gnw_case_t *t, int idx)
{
	wifi_neighbor_ap2_t **ap = (t->args & 1) ? NULL : ap_slot();
	unsigned int *sz = (t->args & 2) ? NULL : sz_slot();

	errno = 0;
	poison(1, t);
	int ret = hwr_wifi_getNeighboringWiFiStatus(idx, ap, sz);
	poison(0, t);
	return ret;
}

static int streq(const char *got, const char *exp, const char *field, int i)
{
	if (strcmp(got, exp) == 0) return 1;
	snprintf(why, sizeof(why), "entry %d %s = '%s', expected '%s'", i, field, got, exp);
	return 0;
}
#define CHK_STR(f, e)  if (!streq(a->f, tp->e, #f, i)) return 0
#define CHK_NUM(f, v)  if ((long)a->f != (long)(v)) { snprintf(why, sizeof(why), "entry %d %s = %ld, expected %ld", i, #f, (long)a->f, (long)(v)); return 0; }

static int check_entry(const wifi_neighbor_ap2_t *a, const gnw_tmpl_t *tp, int i)
{
	CHK_STR(ap_SSID, ssid); CHK_STR(ap_BSSID, e_bssid); CHK_STR(ap_Mode, e_mode);
	CHK_NUM(ap_Channel, tp->e_channel); CHK_NUM(ap_SignalStrength, tp->rssi); CHK_NUM(ap_freq, tp->freq);
	CHK_STR(ap_SecurityModeEnabled, e_sec); CHK_STR(ap_EncryptionMode, e_enc); CHK_STR(ap_OperatingFrequencyBand, e_band);
	CHK_STR(ap_SupportedStandards, e_supp_std); CHK_STR(ap_OperatingStandards, e_oper_std); CHK_STR(ap_OperatingChannelBandwidth, e_bw);
	CHK_STR(ap_BasicDataTransferRates, e_basic); CHK_STR(ap_SupportedDataTransferRates, e_supp_rates);
	CHK_NUM(ap_BeaconPeriod, tp->beacon); CHK_NUM(ap_Noise, tp->noise); CHK_NUM(ap_DTIMPeriod, tp->dtim); CHK_NUM(ap_ChannelUtilization, tp->util);
	CHK_NUM(bss_load_element_present, tp->load ? 1 : 0); CHK_NUM(ap_StaCount, tp->load ? tp->sta : 0);
	return 1;
}

/* results of the row that pass the scan frequency filter, in map order */
static int expected_list(const gnw_case_t *t, int *ids)
{
	int n = 0;

	for (int i = 0; i < t->nbss; i++) {
		unsigned freq = gnw_tmpl[t->bss[i]].freq; int pass = (t->nfilt == 0);
		for (int k = 0; k < t->nfilt; k++) if (t->filt[k] == freq) pass = 1;
		if (pass) ids[n++] = t->bss[i];
	}
	return n;
}

/* checks of one call; first = 1 for the first call of the row */
static int check_call(const gnw_case_t *t, int ret, int exp_ret, int untouched, int again)
{
	int ids[GNW_MAXB], n = 0;

	if (ret != exp_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, exp_ret); return 0; }
	if (again && errno != EAGAIN) { snprintf(why, sizeof(why), "errno %d, expected EAGAIN", errno); return 0; }
	if (t->args) return 1;                                      /* NULL output pointer: nothing to look at */
	if (untouched) {
		if (*ap_slot() != STALE_PTR || *sz_slot() != 99) { snprintf(why, sizeof(why), "outputs were modified on an early error return"); return 0; }
		return 1;
	}
	if (exp_ret != WIFI_HAL_SUCCESS) {
		if (*ap_slot() != NULL || *sz_slot() != 0) { snprintf(why, sizeof(why), "copy error: *array=%p *size=%u, expected NULL and 0", (void *)*ap_slot(), *sz_slot()); return 0; }
		return 1;
	}
	n = expected_list(t, ids);
	if (*sz_slot() != (unsigned)n) { snprintf(why, sizeof(why), "*size = %u, expected %d", *sz_slot(), n); return 0; }
	if ((n == 0) != (*ap_slot() == NULL)) { snprintf(why, sizeof(why), "array %s for %d results", *ap_slot() ? "not NULL" : "NULL", n); return 0; }
	for (int i = 0; i < n; i++) if (!check_entry(&(*ap_slot())[i], &gnw_tmpl[ids[i]], i)) return 0;
	return 1;
}

static void release(void)
{
	if (*ap_slot() != STALE_PTR) free(*ap_slot());
	*ap_slot() = STALE_PTR;
}

static int run_one(const gnw_case_t *t)
{
	int idx = gnw_resolve_index(t->radio_index), ok;
	gnw_interface_t *si = construct_wifi_getNeighboringWiFiStatus_input(t);

	if (t->radio_index < 0 || t->radio_index == (int)0x80000000) idx = t->radio_index;
	why[0] = 0;
	memset(hwr_log_buf, 0, HWR_LOG_SZ);
	memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);
	prefill();

	int ret = test_wifi_getNeighboringWiFiStatus(t, idx);
	int early = (t->expected_ret != WIFI_HAL_SUCCESS) && t->exp_untouched;
	ok = check_call(t, ret, t->expected_ret, early, t->calls == 1 && t->exp_again);
	if (ok && t->calls == 2) {
		release(); prefill();
		ret = test_wifi_getNeighboringWiFiStatus(t, idx);
		ok = check_call(t, ret, t->expected_ret2, 1, t->exp_again);
	}
	if (ok && si->scan_state != t->exp_state) { snprintf(why, sizeof(why), "scan_state %d, expected %d", si->scan_state, t->exp_state); ok = 0; }
	if (ok && (int)si->scan_has_results != t->exp_results) { snprintf(why, sizeof(why), "scan_has_results %u, expected %d", si->scan_has_results, t->exp_results); ok = 0; }
	if (ok && hwr_guard_slab[0] != 0xA5) { snprintf(why, sizeof(why), "guard slab modified"); ok = 0; }
	release();
	return ok;
}

extern "C" void run_all_tests_wifi_getNeighboringWiFiStatus(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; wifi_getNeighboringWiFiStatus_suite[i].test_name != NULL; i++) {
		gnw_case_t *test = &wifi_getNeighboringWiFiStatus_suite[i];

		printf("--- Running Test: %s ---\n", test->test_name);
		if (run_one(test)) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=%d) %s =====\n", test->test_name, test->expected_ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_getNeighboringWiFiStatus: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
