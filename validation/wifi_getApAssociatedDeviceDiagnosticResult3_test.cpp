/*
 * TEST RUNNER: wifi_getApAssociatedDeviceDiagnosticResult3_test
 *
 * Same shape as the other *_test.cpp runners: test_wifi_getApAssociatedDeviceDiagnosticResult3() POISONS what the function must not touch, calls the
 * handler and unpoisons; run_all_tests compares the result.  The runner owns the output slots (array pointer / size) and the nl80211 "world" of the
 * case (stations, failures).  During the call it POISONS the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  The netlink replies are
 * exact-size heap blocks and the MAC list / entry array are heap blocks, so any read or write outside them aborts under ASan.
 * Checks: return value; *size; that the outputs stay untouched on failure paths that must not write them; that on failure *array is NULL and *size 0;
 * no heap block left allocated (MAC list freed, array freed on failure); and for every entry the MAC, byte / packet / error / retry counters, RSSI,
 * the downlink / uplink rate (bitrate32 * 100), the operating standard (TX rate flags first, RX as fallback) and the authentication state.
 * Rows with last = 1 are the invalid-input / failure rows that crash or leak the original: they run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hwr_gad.h"
#include <sanitizer/asan_interface.h>

static gad_interface_t iface_obj;
static char why[200];
static wifi_associated_dev3_t *sentinel_arr = (wifi_associated_dev3_t *)0x1234;
#define SENT_SIZE 0xDEADu

/* poison, call, unpoison -- returns what wifi_getApAssociatedDeviceDiagnosticResult3 returned */
int test_wifi_getApAssociatedDeviceDiagnosticResult3(const gad_case_t *t, wifi_associated_dev3_t **arr, UINT *size)
{
	wifi_associated_dev3_t **pa = (t->args & 1) ? NULL : arr;
	UINT *ps = (t->args & 2) ? NULL : size;

	__asan_poison_memory_region(hwr_guard_slab, HWR_GUARD_SZ);
	__asan_poison_memory_region(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
	int ret = hwr_wifi_getApAssociatedDeviceDiagnosticResult3(t->ap_index, pa, ps);
	__asan_unpoison_memory_region(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
	__asan_unpoison_memory_region(hwr_guard_slab, HWR_GUARD_SZ);
	return ret;
}

static void setup(const gad_case_t *t)
{
	gad_world_t *w = &hwr_gad_world;

	memset(w, 0, sizeof(*w));
	memset(hwr_log_buf, 0, HWR_LOG_SZ);
	memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);
	memset(&iface_obj, 0, sizeof(iface_obj));
	iface_obj.index = 7; iface_obj.phy_index = 1;
	iface_obj.vap_index = (t->has_iface == 2) ? (unsigned)t->ap_index + 1u : (unsigned)t->ap_index;
	w->iface = t->has_iface ? &iface_obj : NULL;
	w->nsta = t->nsta;
	for (int i = 0; i < t->nsta; i++) {
		unsigned char m[6] = { 0x02, 0x11, 0x22, 0x33, (unsigned char)(0x40 + i), (unsigned char)(0x50 + i) };
		memcpy(w->sta[i].mac, m, 6); w->sta[i].tmpl = t->tmpl[i];
	}
	w->list_cmd_fail = t->list_cmd_fail; w->stats_cmd_fail = t->stats_cmd_fail; w->dump_rc = t->dump_rc;
	w->stats_fail_idx = t->stats_fail_idx; w->fail_calloc = t->fail_calloc; w->fail_realloc_at = t->fail_realloc_at; w->quirk = t->quirk;
}

static int check_entry(const wifi_associated_dev3_t *d, int si)
{
	const gad_sta_t *s = &hwr_gad_world.sta[si];
	const gad_tmpl_t *x = &gad_tmpl[s->tmpl];

	if (memcmp(d->cli_MACAddress, s->mac, 6) != 0) { snprintf(why, sizeof(why), "station %d: MAC wrong", si); return 0; }
	if (d->cli_BytesReceived != x->rx_bytes || d->cli_BytesSent != x->tx_bytes) { snprintf(why, sizeof(why), "station %d: byte counters %lu/%lu, expected %u/%u", si, (unsigned long)d->cli_BytesReceived, (unsigned long)d->cli_BytesSent, x->rx_bytes, x->tx_bytes); return 0; }
	if (d->cli_PacketsReceived != x->rx_pkts || d->cli_PacketsSent != x->tx_pkts) { snprintf(why, sizeof(why), "station %d: packet counters wrong", si); return 0; }
	if (d->cli_ErrorsSent != x->tx_failed || d->cli_RetransCount != x->retries) { snprintf(why, sizeof(why), "station %d: errors / retransmissions wrong", si); return 0; }
	if ((unsigned long long)d->cli_RxErrors != x->rx_drop) { snprintf(why, sizeof(why), "station %d: RxErrors wrong", si); return 0; }
	if (d->cli_RSSI != (x->signal ? (int)(signed char)x->signal : 0)) { snprintf(why, sizeof(why), "station %d: RSSI %d wrong", si, d->cli_RSSI); return 0; }
	if (d->cli_LastDataDownlinkRate != x->e_down || d->cli_LastDataUplinkRate != x->e_up) { snprintf(why, sizeof(why), "station %d: rates %u/%u, expected %u/%u", si, d->cli_LastDataDownlinkRate, d->cli_LastDataUplinkRate, x->e_down, x->e_up); return 0; }
	if (strcmp(d->cli_OperatingStandard, x->e_std) != 0) { snprintf(why, sizeof(why), "station %d: standard '%s', expected '%s'", si, d->cli_OperatingStandard, x->e_std); return 0; }
	if ((d->cli_AuthenticationState ? 1 : 0) != x->e_auth) { snprintf(why, sizeof(why), "station %d: authentication state %d, expected %d", si, d->cli_AuthenticationState, x->e_auth); return 0; }
	return 1;
}

/* one call; returns 1 if everything holds.  *got receives the return value */
static int one_call(const gad_case_t *t, int *got)
{
	wifi_associated_dev3_t *arr = sentinel_arr;
	UINT size = SENT_SIZE;
	int expect_n = t->exp_size < 0 ? t->nsta - (t->quirk == 2 ? 1 : 0) : t->exp_size;
	int ok = 1;

	int ret = test_wifi_getApAssociatedDeviceDiagnosticResult3(t, &arr, &size);
	*got = ret;
	int leak = hwr_gad_world.live - (arr != NULL && arr != sentinel_arr ? 1 : 0);

	if (ret != t->expected_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, t->expected_ret); ok = 0; }
	else if (t->exp_untouched && !(t->args & 3) && (arr != sentinel_arr || size != SENT_SIZE)) { snprintf(why, sizeof(why), "outputs written (array %p size %u) although the call must fail early", (void *)arr, size); ok = 0; }
	else if (t->exp_null_out && !(t->args & 3) && (arr != NULL || size != 0)) { snprintf(why, sizeof(why), "after failure *array %p / *size %u, expected NULL / 0", (void *)arr, size); ok = 0; }
	else if (leak != 0) { snprintf(why, sizeof(why), "%d heap block(s) left allocated", leak); ok = 0; }
	else if (!t->exp_untouched && !t->exp_null_out && ret == WIFI_HAL_SUCCESS) {
		if ((int)size != expect_n) { snprintf(why, sizeof(why), "*size %u, expected %d", size, expect_n); ok = 0; }
		else if (expect_n == 0 && arr != NULL) { snprintf(why, sizeof(why), "array not NULL for zero stations"); ok = 0; }
		else {
			int e = 0;
			for (int i = 0; i < t->nsta && ok; i++) {
				if (t->quirk == 2 && i == 0) continue;
				ok = check_entry(&arr[e++], i);
			}
		}
	}
	if (arr != NULL && arr != sentinel_arr) free(arr);
	return ok;
}

static int run_one(const gad_case_t *t)
{
	int ok, got = 0;

	printf("--- Running Test: %s ---\n", t->test_name);
	setup(t);
	why[0] = 0;
	ok = one_call(t, &got);
	if (ok && t->calls > 1) {                       /* second call on the same world: fresh array, same content */
		int r2;
		gad_world_t keep = hwr_gad_world;
		hwr_gad_world.live = 0;
		ok = one_call(t, &r2); (void)keep;
	}
	if (ok) {
		printf("================== %s: \033[32mPASS\033[0m ==============\n", t->test_name);
	} else {
		printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", t->test_name, t->expected_ret, got, why);
	}
	printf("------------------------------------------------------------------------------------------------------------------------------\n");
	return ok;
}

extern "C" void run_all_tests_wifi_getApAssociatedDeviceDiagnosticResult3(void)
{
	int pass = 0, fail = 0;

	/* normal rows first, invalid / failure rows last: the first crash aborts the run, every other row has already reported */
	for (int last = 0; last < 2; last++)
		for (int i = 0; wifi_getApAssociatedDeviceDiagnosticResult3_suite[i].test_name != NULL; i++) {
			if (wifi_getApAssociatedDeviceDiagnosticResult3_suite[i].last != last) continue;
			if (run_one(&wifi_getApAssociatedDeviceDiagnosticResult3_suite[i])) pass++; else fail++;
		}
	printf("\nwifi_getApAssociatedDeviceDiagnosticResult3: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
