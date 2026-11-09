/*
 * UNIT TEST (input constructor): construct_wifi_getNeighboringWiFiStatus
 *
 * wifi_getNeighboringWiFiStatus(radio_index, &array, &size) (platform/banana-pi) forwards to wifi_hal_getNeighboringWiFiStatus
 * (src/wifi_hal.c:3691 -> _wifi_hal_getNeighboringWiFiStatus 3587), which copies the scan results of the radio's private interface
 * (scan_info_ap_map[1]) into a calloc'ed wifi_neighbor_ap2_t array.  The suite crosses: NULL output pointers, radio_index (negative, INT_MIN,
 * MAX_NUM_RADIOS, MAX_NUM_RADIOS-1), radio / private interface missing, the scan state on entry (NONE / ERROR / STARTED / ABORTED) with and without
 * API / TEST results, an empty result map, 1..8 results built from 8 canned BSS templates (2.4 / 5 / 6 GHz, AdHoc, hidden SSID, longest SSID,
 * unknown frequency, a bandwidth list that does not fit ap_OperatingChannelBandwidth), the scan frequency filter (none / one / two / no match /
 * zero value, shrinking the array with realloc), calloc / realloc failures and a second call after the results were handed out.
 * The outputs are prefilled with a stale pointer (0xdeadbeef) and size 99: the early error returns must leave them alone, the others overwrite them.
 *
 * Row layout: see gnw_case_t in hwr_gnw.h.  States: 0 NONE 1 ERROR 2 STARTED 3 ABORTED.  Results flags: 1 API, 2 TEST.  radio_index 100 = MAX_NUM_RADIOS,
 * 101 = MAX_NUM_RADIOS - 1.
 */
#include <initializer_list>
#include <limits.h>
#include <string.h>
#include "hwr_gnw.h"

/* ---- canned scan results ---- */
gnw_tmpl_t gnw_tmpl[GNW_NTMPL] = {
	/* 0: 2.4 GHz infrastructure WPA2, bss load present */
	{ "Home", {0x00,0x11,0x22,0x33,0x44,0x55}, 0x0001, 2437, -50, wifi_security_mode_wpa2_personal, wifi_encryption_aes, WIFI_FREQUENCY_2_4_BAND,
	  WIFI_80211_VARIANT_B | WIFI_80211_VARIANT_G | WIFI_80211_VARIANT_N, WIFI_80211_VARIANT_G | WIFI_80211_VARIANT_N, WIFI_CHANNELBANDWIDTH_20MHZ,
	  WIFI_BITRATE_1MBPS | WIFI_BITRATE_2MBPS, WIFI_BITRATE_1MBPS | WIFI_BITRATE_2MBPS | WIFI_BITRATE_5_5MBPS | WIFI_BITRATE_11MBPS,
	  100, 2, 10, -90, 1, 5,
	  "Infrastructure", "00:11:22:33:44:55", "WPA2-Personal", "AES", "2.4GHz", "b,g,n", "g,n", "20MHz", "1Mbps,2Mbps", "1Mbps,2Mbps,5.5Mbps,11Mbps", 6 },
	/* 1: 5 GHz WPA3 */
	{ "Office5G", {0xaa,0xbb,0xcc,0xdd,0xee,0xff}, 0x0001, 5180, -61, wifi_security_mode_wpa3_personal, wifi_encryption_aes, WIFI_FREQUENCY_5_BAND,
	  WIFI_80211_VARIANT_A | WIFI_80211_VARIANT_N | WIFI_80211_VARIANT_AC, WIFI_80211_VARIANT_AC, WIFI_CHANNELBANDWIDTH_80MHZ,
	  WIFI_BITRATE_6MBPS, WIFI_BITRATE_6MBPS | WIFI_BITRATE_54MBPS,
	  200, 1, 33, -95, 0, 0,
	  "Infrastructure", "aa:bb:cc:dd:ee:ff", "WPA3-Personal", "AES", "5GHz", "a,ac", "ac", "80MHz", "6Mbps", "6Mbps,54Mbps", 36 },
	/* 2: 6 GHz, WPA3 transition is reported as WPA3-Personal on 6 GHz */
	{ "Lounge6G", {0x02,0x00,0x00,0x00,0x00,0x06}, 0x0001, 5955, -70, wifi_security_mode_wpa3_transition, wifi_encryption_aes_tkip, WIFI_FREQUENCY_6_BAND,
	  WIFI_80211_VARIANT_AX | WIFI_80211_VARIANT_BE, WIFI_80211_VARIANT_AX, WIFI_CHANNELBANDWIDTH_160MHZ,
	  WIFI_BITRATE_24MBPS, WIFI_BITRATE_24MBPS,
	  100, 3, 5, -100, 1, 12,
	  "Infrastructure", "02:00:00:00:00:06", "WPA3-Personal", "AES+TKIP", "6GHz", "ax,be", "ax", "160MHz", "24Mbps", "24Mbps", 1 },
	/* 3: AdHoc on channel 14, open */
	{ "AdHocNet", {0x10,0x20,0x30,0x40,0x50,0x60}, 0x0002, 2484, -80, wifi_security_mode_none, wifi_encryption_none, WIFI_FREQUENCY_2_4_BAND,
	  WIFI_80211_VARIANT_B, WIFI_80211_VARIANT_B, WIFI_CHANNELBANDWIDTH_20MHZ,
	  WIFI_BITRATE_1MBPS, WIFI_BITRATE_1MBPS,
	  50, 1, 0, -85, 0, 0,
	  "AdHoc", "10:20:30:40:50:60", "None", "None", "2.4GHz", "b", "b", "20MHz", "1Mbps", "1Mbps", 14 },
	/* 4: frequency that has no channel: the entry is still returned, with channel 0 */
	{ "BadFreq", {0x01,0x02,0x03,0x04,0x05,0x06}, 0x0001, 1234, -77, wifi_security_mode_wpa_personal, wifi_encryption_tkip, WIFI_FREQUENCY_2_4_BAND,
	  WIFI_80211_VARIANT_G, WIFI_80211_VARIANT_G, WIFI_CHANNELBANDWIDTH_20MHZ,
	  WIFI_BITRATE_12MBPS, WIFI_BITRATE_12MBPS,
	  100, 1, 1, -88, 0, 0,
	  "Infrastructure", "01:02:03:04:05:06", "WPA-Personal", "TKIP", "2.4GHz", "g", "g", "20MHz", "12Mbps", "12Mbps", 0 },
	/* 5: longest SSID the scan code stores (31 characters + NUL) */
	{ "ABCDEFGHIJKLMNOPQRSTUVWXYZ01234", {0xde,0xad,0xbe,0xef,0x00,0x01}, 0x0001, 2412, -45, wifi_security_mode_wpa_wpa2_enterprise, wifi_encryption_aes_tkip, WIFI_FREQUENCY_2_4_BAND,
	  WIFI_80211_VARIANT_N, WIFI_80211_VARIANT_N, WIFI_CHANNELBANDWIDTH_40MHZ,
	  WIFI_BITRATE_9MBPS, WIFI_BITRATE_9MBPS,
	  100, 4, 20, -92, 1, 3,
	  "Infrastructure", "de:ad:be:ef:00:01", "WPA-WPA2-Enterprise", "AES+TKIP", "2.4GHz", "n", "n", "40MHz", "9Mbps", "9Mbps", 1 },
	/* 6: three bandwidth bits: "20MHz,40MHz,80MHz" is 17 characters and does not fit ap_OperatingChannelBandwidth[16] */
	{ "WideBw", {0x0a,0x0b,0x0c,0x0d,0x0e,0x0f}, 0x0001, 5500, -66, wifi_security_mode_wpa2_enterprise, wifi_encryption_aes, WIFI_FREQUENCY_5_BAND,
	  WIFI_80211_VARIANT_AC, WIFI_80211_VARIANT_AC, WIFI_CHANNELBANDWIDTH_20MHZ | WIFI_CHANNELBANDWIDTH_40MHZ | WIFI_CHANNELBANDWIDTH_80MHZ,
	  WIFI_BITRATE_36MBPS, WIFI_BITRATE_36MBPS,
	  100, 2, 40, -96, 0, 0,
	  "Infrastructure", "0a:0b:0c:0d:0e:0f", "WPA2-Enterprise", "AES", "5GHz", "ac", "ac", "20MHz,40MHz,", "36Mbps", "36Mbps", 100 },
	/* 7: hidden (empty) SSID, IBSS|ESS (AdHoc wins), 5 GHz lower band, unknown encryption */
	{ "", {0xf0,0xf1,0xf2,0xf3,0xf4,0xf5}, 0x0003, 5745, -58, wifi_security_mode_wpa3_enterprise, wifi_encryption_tkip, WIFI_FREQUENCY_5L_BAND,
	  WIFI_80211_VARIANT_AX, WIFI_80211_VARIANT_AX, WIFI_CHANNELBANDWIDTH_80MHZ,
	  WIFI_BITRATE_18MBPS, WIFI_BITRATE_18MBPS,
	  100, 1, 7, -91, 1, 1,
	  "AdHoc", "f0:f1:f2:f3:f4:f5", "WPA3-Enterprise", "TKIP", "5GHz", "ax", "ax", "80MHz", "18Mbps", "18Mbps", 149 },
};

/* ---- the world of one row (runner-owned) ---- */
gnw_map_t        gnw_map0, gnw_map1;
wifi_bss_info_t  gnw_store[GNW_MAXB];
unsigned int     gnw_filt_slab[8];
gnw_interface_t  gnw_iface;
gnw_radio_t      gnw_radio;

int gnw_resolve_index(int idx) { return idx == 100 ? MAX_NUM_RADIOS : idx == 101 ? MAX_NUM_RADIOS - 1 : idx; }

static void build_bss(wifi_bss_info_t *b, const gnw_tmpl_t *t)
{
	memset(b, 0, sizeof(*b));
	strcpy(b->ssid, t->ssid);
	memcpy(b->bssid, t->bssid, 6);
	b->caps = t->caps; b->freq = t->freq; b->rssi = t->rssi;
	b->sec_mode = (wifi_security_modes_t)t->sec_mode; b->enc_method = (wifi_encryption_method_t)t->enc_method; b->oper_freq_band = (wifi_freq_bands_t)t->band;
	b->supp_standards = (wifi_ieee80211Variant_t)t->supp_std; b->oper_standards = (wifi_ieee80211Variant_t)t->oper_std;
	b->supp_chan_bw = (wifi_channelBandwidth_t)t->bw; b->oper_chan_bw = (wifi_channelBandwidth_t)t->bw;
	b->basic_rates = (wifi_bitrate_t)t->basic; b->supp_rates = (wifi_bitrate_t)t->supp_rates;
	b->beacon_int = t->beacon; b->dtim_period = t->dtim; b->chan_utilization = t->util; b->noise = t->noise;
	b->bss_load_element_present = t->load; b->station_cnt = t->sta;
}

gnw_interface_t *construct_wifi_getNeighboringWiFiStatus_input(const gnw_case_t *t)
{
	memset(&hwr_gnw_world, 0, sizeof(hwr_gnw_world));
	memset(&gnw_iface, 0, sizeof(gnw_iface)); memset(&gnw_radio, 0, sizeof(gnw_radio));
	memset(&gnw_map0, 0, sizeof(gnw_map0)); memset(&gnw_map1, 0, sizeof(gnw_map1));
	memset(gnw_store, 0xA5, sizeof(gnw_store));
	memset(gnw_filt_slab, 0xA5, sizeof(gnw_filt_slab));
	for (int i = 0; i < t->nbss && i < GNW_MAXB; i++) { build_bss(&gnw_store[i], &gnw_tmpl[t->bss[i]]); gnw_map1.items[i] = &gnw_store[i]; }
	gnw_map1.n = t->nbss;
	for (int i = t->nbss; i < GNW_MAXB; i++) gnw_map1.items[i] = (wifi_bss_info_t *)(unsigned long)0xdeadbeefUL;   /* unused slots: poisoned by the runner */

	pthread_mutex_init(&gnw_iface.scan_state_mutex, NULL);
	pthread_mutex_init(&gnw_iface.scan_info_mutex, NULL);
	pthread_mutex_init(&gnw_iface.scan_info_ap_mutex, NULL);
	snprintf(gnw_iface.name, sizeof(gnw_iface.name), "wlan0");
	snprintf(gnw_radio.name, sizeof(gnw_radio.name), "wlan0");
	gnw_iface.scan_state = t->pre_state; gnw_iface.scan_has_results = t->pre_results;
	gnw_iface.scan_info_ap_map[0] = &gnw_map0; gnw_iface.scan_info_ap_map[1] = &gnw_map1;
	for (int i = 0; i < t->nfilt && i < 3; i++) gnw_filt_slab[i] = t->filt[i];
	gnw_iface.scan_filter.num = t->nfilt; gnw_iface.scan_filter.values = t->nfilt ? gnw_filt_slab : NULL;

	hwr_gnw_world.radio = t->has_radio ? &gnw_radio : NULL;
	hwr_gnw_world.radio_index = (unsigned)gnw_resolve_index(t->radio_index);
	if (t->radio_index < 0 || t->radio_index == INT_MIN) hwr_gnw_world.radio_index = 0;
	hwr_gnw_world.priv_iface = t->has_priv ? &gnw_iface : NULL;
	hwr_gnw_world.fail_calloc = t->fail_calloc; hwr_gnw_world.fail_realloc = t->fail_realloc;
	return &gnw_iface;
}

#define OK   WIFI_HAL_SUCCESS
#define ERR  WIFI_HAL_ERROR
#define INV  WIFI_HAL_INVALID_ARGUMENTS
#define NRD  WIFI_HAL_NOT_READY
#define NOB  0, {0}
#define NOF  0, {0,0,0}
#define ALLB 8, {0,1,2,3,4,5,6,7}

/* name, radio, args, has_radio, has_priv, pre_state, pre_results, nbss{bss}, nfilt{filt}, fail_calloc, fail_realloc, calls, ret, ret2, exp_state, exp_results, exp_again, exp_untouched */
gnw_case_t wifi_getNeighboringWiFiStatus_suite[] = {
	/* ---- arguments ---- */
	{ "array_ptr_null",                0, 1, 1,1, 0,1, 1,{0}, NOF, 0,0, 1, INV,0, 0,1, 0,1 },
	{ "size_ptr_null",                 0, 2, 1,1, 0,1, 1,{0}, NOF, 0,0, 1, INV,0, 0,1, 0,1 },
	{ "both_ptrs_null",                0, 3, 1,1, 0,1, 1,{0}, NOF, 0,0, 1, INV,0, 0,1, 0,1 },
	{ "radio_index_negative",         -1, 0, 1,1, 0,1, 1,{0}, NOF, 0,0, 1, INV,0, 0,1, 0,1 },
	{ "radio_index_int_min",      INT_MIN, 0, 1,1, 0,1, 1,{0}, NOF, 0,0, 1, INV,0, 0,1, 0,1 },
	{ "radio_index_max_radios",      100, 0, 1,1, 0,1, 1,{0}, NOF, 0,0, 1, INV,0, 0,1, 0,1 },
	{ "radio_index_last_valid",      101, 0, 1,1, 0,1, 1,{0}, NOF, 0,0, 1, OK, 0, 0,0, 0,0 },
	{ "radio_index_0_valid",           0, 0, 1,1, 0,1, 1,{0}, NOF, 0,0, 1, OK, 0, 0,0, 0,0 },
	/* ---- lookups ---- */
	{ "radio_not_found",               0, 0, 0,1, 0,1, 1,{0}, NOF, 0,0, 1, ERR,0, 0,1, 0,1 },
	{ "private_interface_not_found",   0, 0, 1,0, 0,1, 1,{0}, NOF, 0,0, 1, ERR,0, 0,1, 0,1 },
	/* ---- scan state on entry ---- */
	{ "state_none_no_results",         0, 0, 1,1, 0,0, NOB, NOF, 0,0, 1, ERR,0, 0,0, 0,1 },
	{ "state_none_test_results_only",  0, 0, 1,1, 0,2, 1,{0}, NOF, 0,0, 1, ERR,0, 0,2, 0,1 },
	{ "state_aborted_reset_to_none",   0, 0, 1,1, 3,0, NOB, NOF, 0,0, 1, ERR,0, 0,0, 0,1 },
	{ "state_aborted_wins_over_results", 0, 0, 1,1, 3,1, 1,{0}, NOF, 0,0, 1, ERR,0, 0,1, 0,1 },
	{ "state_error_reset_to_none",     0, 0, 1,1, 1,0, NOB, NOF, 0,0, 1, ERR,0, 0,0, 0,1 },
	{ "state_error_wins_over_results", 0, 0, 1,1, 1,1, 1,{0}, NOF, 0,0, 1, ERR,0, 0,1, 0,1 },
	{ "state_started_no_results",      0, 0, 1,1, 2,0, NOB, NOF, 0,0, 1, NRD,0, 2,0, 1,1 },
	{ "state_started_test_results_only", 0, 0, 1,1, 2,2, 1,{0}, NOF, 0,0, 1, NRD,0, 2,2, 1,1 },
	/* ---- results handed out ---- */
	{ "none_api_results_empty_map",    0, 0, 1,1, 0,1, NOB, NOF, 0,0, 1, OK, 0, 0,0, 0,0 },
	{ "none_api_results_one_bss",      0, 0, 1,1, 0,1, 1,{0}, NOF, 0,0, 1, OK, 0, 0,0, 0,0 },
	{ "started_with_api_results",      0, 0, 1,1, 2,1, 1,{1}, NOF, 0,0, 1, OK, 0, 2,0, 0,0 },
	{ "api_and_test_flags_only_api_cleared", 0, 0, 1,1, 0,3, 1,{0}, NOF, 0,0, 1, OK, 0, 0,2, 0,0 },
	{ "two_bss_2g_5g",                 0, 0, 1,1, 0,1, 2,{0,1}, NOF, 0,0, 1, OK, 0, 0,0, 0,0 },
	{ "four_bss_2g_5g_6g_adhoc",       0, 0, 1,1, 0,1, 4,{0,1,2,3}, NOF, 0,0, 1, OK, 0, 0,0, 0,0 },
	{ "eight_bss_all_templates",       0, 0, 1,1, 0,1, ALLB, NOF, 0,0, 1, OK, 0, 0,0, 0,0 },
	{ "eight_bss_same_template",       0, 0, 1,1, 0,1, 8,{5,5,5,5,5,5,5,5}, NOF, 0,0, 1, OK, 0, 0,0, 0,0 },
	{ "adhoc_channel_14",              0, 0, 1,1, 0,1, 1,{3}, NOF, 0,0, 1, OK, 0, 0,0, 0,0 },
	{ "six_ghz_wpa3_transition",       0, 0, 1,1, 0,1, 1,{2}, NOF, 0,0, 1, OK, 0, 0,0, 0,0 },
	{ "hidden_ssid_adhoc_wins",        0, 0, 1,1, 0,1, 1,{7}, NOF, 0,0, 1, OK, 0, 0,0, 0,0 },
	{ "longest_ssid_31_chars",         0, 0, 1,1, 0,1, 1,{5}, NOF, 0,0, 1, OK, 0, 0,0, 0,0 },
	{ "unknown_frequency_channel_0",   0, 0, 1,1, 0,1, 1,{4}, NOF, 0,0, 1, OK, 0, 0,0, 0,0 },
	{ "bandwidth_list_does_not_fit",   0, 0, 1,1, 0,1, 1,{6}, NOF, 0,0, 1, OK, 0, 0,0, 0,0 },
	/* ---- scan frequency filter ---- */
	{ "filter_2g_only_shrinks_array",  0, 0, 1,1, 0,1, 3,{0,1,2}, 1,{2437}, 0,0, 1, OK, 0, 0,0, 0,0 },
	{ "filter_5g_only",                0, 0, 1,1, 0,1, 3,{0,1,2}, 1,{5180}, 0,0, 1, OK, 0, 0,0, 0,0 },
	{ "filter_two_freqs",              0, 0, 1,1, 0,1, 3,{0,1,2}, 2,{2437,5955}, 0,0, 1, OK, 0, 0,0, 0,0 },
	{ "filter_all_match_no_shrink",    0, 0, 1,1, 0,1, 2,{0,1}, 2,{2437,5180}, 0,0, 1, OK, 0, 0,0, 0,0 },
	{ "filter_no_match_all_dropped",   0, 0, 1,1, 0,1, 3,{0,1,2}, 1,{9999}, 0,0, 1, OK, 0, 0,0, 0,0 },
	{ "filter_zero_value_drops_all",   0, 0, 1,1, 0,1, 2,{0,1}, 1,{0}, 0,0, 1, OK, 0, 0,0, 0,0 },
	{ "filter_on_empty_map",           0, 0, 1,1, 0,1, NOB, 1,{2437}, 0,0, 1, OK, 0, 0,0, 0,0 },
	/* ---- allocation failures ---- */
	{ "calloc_fails",                  0, 0, 1,1, 0,1, 2,{0,1}, NOF, 1,0, 1, ERR,0, 0,0, 0,0 },
	{ "calloc_fails_empty_map_no_alloc", 0, 0, 1,1, 0,1, NOB, NOF, 1,0, 1, OK, 0, 0,0, 0,0 },
	{ "realloc_fails_original_kept",   0, 0, 1,1, 0,1, 3,{0,1,2}, 1,{2437}, 0,1, 1, OK, 0, 0,0, 0,0 },
	/* ---- second call ---- */
	{ "none_api_results_second_call_not_triggered", 0, 0, 1,1, 0,1, 1,{0}, NOF, 0,0, 2, OK, ERR, 0,0, 0,0 },
	{ "started_api_results_second_call_not_ready",  0, 0, 1,1, 2,1, 1,{0}, NOF, 0,0, 2, OK, NRD, 2,0, 1,0 },
	{ NULL }
};
