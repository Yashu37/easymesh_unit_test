/*
 * TEST RUNNER: bcm_wifi_getApAssociatedDeviceDiagnosticResult3_test
 *
 * Same shape as the other *_test.cpp runners: test_bcm_wifi_getApAssociatedDeviceDiagnosticResult3() POISONS what the function must not touch, calls the
 * handler and unpoisons; run_all_tests compares the result.  The runner owns the output slots (array pointer / size) and the kernel "world" of the case.
 * During the call it POISONS the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  The netlink replies are exact-size heap blocks and the MAC
 * list / entry array are heap blocks, so any read or write outside them aborts under ASan.
 * Checks: return value; *size; outputs untouched on the failure paths that must not write them; *array NULL / *size 0 after a failure that writes them;
 * no heap block left allocated; and for every entry the MAC, every statistic (rates, RSSI, counters, SNR, MLD fields, power save), the operating
 * standard / bandwidth strings, the derived Ack / NoAck / PacketsSent counters, and that the neighbouring field cli_IPAddress stayed zero.
 * Rows with last = 1 are the invalid-input / failure rows that crash or corrupt the original: they run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hwr_bga.h"
#include <sanitizer/asan_interface.h>

static bga_interface_t iface_obj;
static char why[200];
static wifi_associated_dev3_t *sentinel_arr = (wifi_associated_dev3_t *)0x1234;
#define SENT_SIZE 0xDEADu

/* poison, call, unpoison -- returns what the function returned */
int test_bcm_wifi_getApAssociatedDeviceDiagnosticResult3(const bga_case_t *t, wifi_associated_dev3_t **arr, UINT *size)
{
	wifi_associated_dev3_t **pa = (t->args & 1) ? NULL : arr;
	UINT *ps = (t->args & 2) ? NULL : size;

	__asan_poison_memory_region(hwr_guard_slab, HWR_GUARD_SZ);
	__asan_poison_memory_region(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
	int ret = hwr_bcm_wifi_getApAssociatedDeviceDiagnosticResult3(t->ap_index, pa, ps);
	__asan_unpoison_memory_region(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
	__asan_unpoison_memory_region(hwr_guard_slab, HWR_GUARD_SZ);
	return ret;
}

static void setup(const bga_case_t *t)
{
	bga_world_t *w = &hwr_bga_world;

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
		memcpy(w->mac[i], m, 6);
	}
	w->list_cmd_fail = t->list_cmd_fail; w->stats_cmd_fail = t->stats_cmd_fail; w->dump_rc = t->dump_rc;
	w->stats_fail_idx = t->stats_fail_idx;
	w->fail_calloc = t->fail_calloc; w->calloc_limit = t->calloc_limit;
	w->sta_num = t->sta_num; w->list_entries = t->list_entries; w->list_mac_len = t->list_mac_len;
	w->tx_bytes = t->tx_bytes; w->tx_pkts = t->tx_pkts; w->failed = t->failed; w->std = t->std; w->bw = t->bw;
	w->mld = t->mld; w->mld_mac_len = t->mld_mac_len; w->mac_len = t->mac_len; w->omit = t->omit;
}

static const char *std_str(unsigned v)
{
	static const char *n[] = { "", "a", "b", "g", "n", "ac", "ad", "ax", "be" };
	return v < 9 ? n[v] : "";
}
static const char *bw_str(unsigned v)
{
	static const char *n[] = { "", "20", "40", "80", "160", "320" };
	return v < 6 ? n[v] : "";
}

#define CHK(cond, ...) do { if (!(cond)) { snprintf(why, sizeof(why), __VA_ARGS__); return 0; } } while (0)

static int check_entry(const wifi_associated_dev3_t *d, int i, const bga_case_t *t)
{
	unsigned long noack = t->failed, ack, pkts;
	unsigned char mld_mac[6] = { 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5 }, zero[6] = { 0 };
	static unsigned char zero64[64];

	CHK(memcmp(d->cli_MACAddress, hwr_bga_world.mac[i], 6) == 0, "station %d: MAC wrong", i);
	CHK(memcmp(d->cli_IPAddress, zero64, sizeof(zero64)) == 0, "station %d: cli_IPAddress (the field after the MAC) was overwritten", i);
	CHK((d->cli_AuthenticationState ? 1 : 0) == ((i & 1) == 0), "station %d: authentication state wrong", i);
	CHK(d->cli_LastDataUplinkRate == 1000u + i && d->cli_LastDataDownlinkRate == 2000u + i, "station %d: rates wrong", i);
	CHK(d->cli_RSSI == -50 - i && d->cli_SignalStrength == -50 - i, "station %d: RSSI %d wrong", i, d->cli_RSSI);
	CHK(d->cli_MinRSSI == -90 && d->cli_MaxRSSI == -30, "station %d: min / max RSSI wrong", i);
	CHK(d->cli_Retransmissions == 5u + i, "station %d: retransmissions wrong", i);
	CHK(d->cli_Active == 1, "station %d: active wrong", i);
	CHK(strcmp(d->cli_OperatingStandard, std_str(t->std)) == 0, "station %d: standard '%s', expected '%s'", i, d->cli_OperatingStandard, std_str(t->std));
	CHK(strcmp(d->cli_OperatingChannelBandwidth, bw_str(t->bw)) == 0, "station %d: bandwidth '%s', expected '%s'", i, d->cli_OperatingChannelBandwidth, bw_str(t->bw));
	CHK(d->cli_SNR == 30 + i, "station %d: SNR wrong", i);
	CHK(d->cli_BytesSent == t->tx_bytes && d->cli_BytesReceived == 123456ULL + i, "station %d: byte counters wrong", i);
	CHK(d->cli_AuthenticationFailures == 2 && d->cli_Associations == 4, "station %d: auth failures / associations wrong", i);
	CHK(d->cli_PacketsReceived == 888 && d->cli_ErrorsSent == 9 && d->cli_RetransCount == 11, "station %d: counters wrong", i);
	CHK(d->cli_FailedRetransCount == t->failed && d->cli_RetryCount == 13 && d->cli_MultipleRetryCount == 14, "station %d: retry counters wrong", i);
	CHK(d->cli_MaxDownlinkRate == 1200 && d->cli_MaxUplinkRate == 600, "station %d: max rates wrong", i);
	CHK(d->cli_capableNumSpatialStreams == 2, "station %d: capable spatial streams %u, expected 2", i, d->cli_capableNumSpatialStreams);
	CHK(d->cli_activeNumSpatialStreams == 1, "station %d: active spatial streams wrong", i);
	CHK(d->cli_TxFrames == 500 && d->cli_RxRetries == 6 && d->cli_RxErrors == 8, "station %d: frame counters wrong", i);
	CHK(d->cli_MLDEnable == (t->mld >= 0 ? t->mld : 0), "station %d: MLD enable wrong", i);
	CHK(memcmp(d->cli_MLDAddr, t->mld_mac_len >= 6 ? mld_mac : zero, 6) == 0, "station %d: MLD address wrong", i);
	CHK(d->cli_PowerSaveMode == 1 && d->cli_sleepTime == 77, "station %d: power save fields wrong", i);
	/* derived counters (platform.c: the packets / bytes arithmetic after the attributes) */
	pkts = t->tx_pkts;
	ack = (t->tx_bytes / 1470 < pkts) ? pkts - noack : t->tx_bytes / 1470 - noack;
	pkts = ack + noack;
	CHK(d->cli_DataFramesSentNoAck == noack && d->cli_DataFramesSentAck == ack && d->cli_PacketsSent == pkts,
	    "station %d: derived ack/noack/packets %lu/%lu/%lu, expected %lu/%lu/%lu", i, d->cli_DataFramesSentAck, d->cli_DataFramesSentNoAck, d->cli_PacketsSent, ack, noack, pkts);
	return 1;
}

/* one call; returns 1 if everything holds.  *got receives the return value */
static int one_call(const bga_case_t *t, int *got)
{
	wifi_associated_dev3_t *arr = sentinel_arr;
	UINT size = SENT_SIZE;
	int expect_n = t->exp_size < 0 ? t->nsta : t->exp_size;
	int ok = 1;

	int ret = test_bcm_wifi_getApAssociatedDeviceDiagnosticResult3(t, &arr, &size);
	*got = ret;
	int leak = hwr_bga_world.live - (arr != NULL && arr != sentinel_arr ? 1 : 0);

	if (ret != t->expected_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, t->expected_ret); ok = 0; }
	else if (t->exp_untouched && !(t->args & 3) && (arr != sentinel_arr || size != SENT_SIZE)) { snprintf(why, sizeof(why), "outputs written (array %p size %u) although the call must fail early", (void *)arr, size); ok = 0; }
	else if (t->exp_null_out && !(t->args & 3) && (arr != NULL || size != 0)) { snprintf(why, sizeof(why), "after failure *array %p / *size %u, expected NULL / 0", (void *)arr, size); ok = 0; }
	else if (leak != 0) { snprintf(why, sizeof(why), "%d heap block(s) left allocated", leak); ok = 0; }
	else if (!t->exp_untouched && !t->exp_null_out && ret == WIFI_HAL_SUCCESS) {
		if ((int)size != expect_n) { snprintf(why, sizeof(why), "*size %u, expected %d", size, expect_n); ok = 0; }
		else if (expect_n == 0 && arr != NULL) { snprintf(why, sizeof(why), "array not NULL for zero stations"); ok = 0; }
		else for (int i = 0; i < expect_n && ok; i++) ok = check_entry(&arr[i], i, t);
	}
	if (arr != NULL && arr != sentinel_arr) free(arr);
	return ok;
}

static int run_one(const bga_case_t *t)
{
	int ok, got = 0;

	printf("--- Running Test: %s ---\n", t->test_name);
	setup(t);
	why[0] = 0;
	ok = one_call(t, &got);
	if (ok && t->calls > 1) {                       /* second call on the same world: fresh array, same content */
		int r2;
		hwr_bga_world.live = 0;
		ok = one_call(t, &r2);
	}
	if (ok) {
		printf("================== %s: \033[32mPASS\033[0m ==============\n", t->test_name);
	} else {
		printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", t->test_name, t->expected_ret, got, why);
	}
	printf("------------------------------------------------------------------------------------------------------------------------------\n");
	return ok;
}

extern "C" void run_all_tests_bcm_wifi_getApAssociatedDeviceDiagnosticResult3(void)
{
	int pass = 0, fail = 0;

	/* normal rows first, invalid / failure rows last: the first crash aborts the run, every other row has already reported */
	for (int last = 0; last < 2; last++)
		for (int i = 0; bcm_wifi_getApAssociatedDeviceDiagnosticResult3_suite[i].test_name != NULL; i++) {
			if (bcm_wifi_getApAssociatedDeviceDiagnosticResult3_suite[i].last != last) continue;
			if (run_one(&bcm_wifi_getApAssociatedDeviceDiagnosticResult3_suite[i])) pass++; else fail++;
		}
	printf("\nwifi_getApAssociatedDeviceDiagnosticResult3 (broadcom): %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
