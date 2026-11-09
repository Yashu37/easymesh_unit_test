/*
 * UNIT TEST (input constructor): construct_wifi_getApAssociatedDeviceDiagnosticResult3
 *
 * wifi_getApAssociatedDeviceDiagnosticResult3(apIndex, &array, &size) (platform/banana-pi) dumps the stations of the AP interface over nl80211
 * (NL80211_CMD_GET_STATION with NLM_F_DUMP, get_sta_list_handler collects the MACs with realloc), calloc's one wifi_associated_dev3_t per station and
 * queries each station (get_sta_stats / get_sta_stats_handler: byte / packet / error / retry counters, signal, TX / RX bitrate, the operating standard
 * from the rate flags, the authorized flag).  The handlers are the real ones, fed with real libnl messages by the nl80211 stub of the handler file.
 * The suite crosses: NULL output pointers, the interface lookup (found / missing / another vap index, negative / INT_MIN / INT_MAX index), 0..8
 * stations, 8 statistics templates (HE / VHT / MCS / legacy-only rates, authorized / not, empty STA_INFO, extreme counters), nl80211 failures (command
 * message NULL for the dump / for a query, the dump failing, a query failing for the first / a later station), calloc failure, realloc failure in the
 * MAC list, malformed MAC attributes (2 bytes in the dump, missing in the dump) and a second call.  Rows named invalid_* run last.
 * The expected result for them is the safe one: WIFI_HAL_ERROR with the outputs untouched for NULL pointers, WIFI_HAL_ERROR with *array NULL / *size 0
 * and no block left allocated for an allocation failure, a malformed attribute ignored (the station is skipped / the reply leaves a zeroed entry).
 *
 * Row layout: see gad_case_t in hwr_gad.h.  Templates: 0 HE tx + VHT rx authorized, 1 VHT tx, 2 MCS tx not authorized, 3 HE rx only (no tx rate),
 * 4 legacy rates only, 5 HE tx not authorized, 6 all-zero counters, no rates, 7 extreme counters.
 */
#include <limits.h>
#include "hwr_gad.h"

gad_tmpl_t gad_tmpl[GAD_NTMPL] = {
	/* rx_bytes tx_bytes rx_pkts tx_pkts tx_failed retries rx_drop signal tx_br32,kind rx_br32,kind flags empty | e_std e_down e_up e_auth */
	{ 1000, 2000, 10, 20, 3, 5, 4ULL,                    -55, 8667, 1, 5000, 2, 1, 0, "ax", 866700, 500000, 1 },
	{ 111, 222, 1, 2, 0, 0, 0ULL,                        -70, 3000, 2, 2000, 1, 1, 0, "ac", 300000, 200000, 1 },
	{ 5, 6, 7, 8, 9, 10, 11ULL,                          -40, 1440, 3,  720, 3, 2, 0, "n",  144000,  72000, 0 },
	{ 1, 1, 1, 1, 1, 1, 1ULL,                            -90,    0, 0, 4000, 1, 0, 0, "ax",      0, 400000, 0 },
	{ 50, 60, 5, 6, 0, 0, 0ULL,                          -60,  540, 4,  540, 4, 1, 0, "",    54000,  54000, 1 },
	{ 70, 80, 7, 8, 1, 2, 3ULL,                          -65, 1201, 1, 1201, 1, 2, 0, "ax", 120100, 120100, 0 },
	{ 0, 0, 0, 0, 0, 0, 0ULL,                              0,    0, 0,    0, 0, 0, 0, "",        0,      0, 0 },
	{ 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFFFFFFFFFULL, 0x80, 1, 1, 1, 2, 1, 0, "ax", 100, 100, 1 },
};

#define ERR  WIFI_HAL_ERROR
#define OK   WIFI_HAL_SUCCESS
#define NT   {0,0,0,0,0,0,0,0}
#define ALL  {0,1,2,3,4,5,6,7}

/* name, ap_index, has_iface, args, nsta{tmpl}, list_cmd_fail, stats_cmd_fail, dump_rc, stats_fail_idx, fail_calloc, fail_realloc_at, quirk,
 * calls, expected_ret, exp_size, exp_untouched, exp_null_out, last */
gad_case_t wifi_getApAssociatedDeviceDiagnosticResult3_suite[] = {
	/* ---- stations ---- */
	{ "no_stations",                     0, 1, 0, 0, NT,               0,0,0,-1,0,0,0, 1, OK, -1, 0,0, 0 },
	{ "one_station_he_tx_vht_rx",        0, 1, 0, 1, {0,0,0,0,0,0,0,0}, 0,0,0,-1,0,0,0, 1, OK, -1, 0,0, 0 },
	{ "one_station_vht_tx",              0, 1, 0, 1, {1,0,0,0,0,0,0,0}, 0,0,0,-1,0,0,0, 1, OK, -1, 0,0, 0 },
	{ "one_station_mcs_not_authorized",  0, 1, 0, 1, {2,0,0,0,0,0,0,0}, 0,0,0,-1,0,0,0, 1, OK, -1, 0,0, 0 },
	{ "one_station_rx_rate_only_he",     0, 1, 0, 1, {3,0,0,0,0,0,0,0}, 0,0,0,-1,0,0,0, 1, OK, -1, 0,0, 0 },
	{ "one_station_legacy_rates_only",   0, 1, 0, 1, {4,0,0,0,0,0,0,0}, 0,0,0,-1,0,0,0, 1, OK, -1, 0,0, 0 },
	{ "one_station_he_not_authorized",   0, 1, 0, 1, {5,0,0,0,0,0,0,0}, 0,0,0,-1,0,0,0, 1, OK, -1, 0,0, 0 },
	{ "one_station_all_zero_counters",      0, 1, 0, 1, {6,0,0,0,0,0,0,0}, 0,0,0,-1,0,0,0, 1, OK, -1, 0,0, 0 },
	{ "one_station_extreme_counters",    0, 1, 0, 1, {7,0,0,0,0,0,0,0}, 0,0,0,-1,0,0,0, 1, OK, -1, 0,0, 0 },
	{ "two_stations",                    0, 1, 0, 2, {0,1,0,0,0,0,0,0}, 0,0,0,-1,0,0,0, 1, OK, -1, 0,0, 0 },
	{ "three_stations",                  0, 1, 0, 3, {2,3,4,0,0,0,0,0}, 0,0,0,-1,0,0,0, 1, OK, -1, 0,0, 0 },
	{ "eight_stations_all_templates",    0, 1, 0, 8, ALL,              0,0,0,-1,0,0,0, 1, OK, -1, 0,0, 0 },
	{ "eight_stations_same_template",    0, 1, 0, 8, {0,0,0,0,0,0,0,0}, 0,0,0,-1,0,0,0, 1, OK, -1, 0,0, 0 },
	{ "two_calls_two_fresh_arrays",      0, 1, 0, 3, {0,1,2,0,0,0,0,0}, 0,0,0,-1,0,0,0, 2, OK, -1, 0,0, 0 },
	/* ---- interface lookup ---- */
	{ "ap_index_15",                    15, 1, 0, 2, {0,1,0,0,0,0,0,0}, 0,0,0,-1,0,0,0, 1, OK, -1, 0,0, 0 },
	{ "ap_index_negative_iface_matches", -1, 1, 0, 1, {0,0,0,0,0,0,0,0}, 0,0,0,-1,0,0,0, 1, OK, -1, 0,0, 0 },
	{ "ap_index_int_max",          INT_MAX, 1, 0, 1, {0,0,0,0,0,0,0,0}, 0,0,0,-1,0,0,0, 1, OK, -1, 0,0, 0 },
	{ "iface_missing",                   0, 0, 0, 2, {0,1,0,0,0,0,0,0}, 0,0,0,-1,0,0,0, 1, ERR, 0, 1,0, 0 },
	{ "iface_other_vap_index",           0, 2, 0, 2, {0,1,0,0,0,0,0,0}, 0,0,0,-1,0,0,0, 1, ERR, 0, 1,0, 0 },
	{ "ap_index_int_min_iface_missing", INT_MIN, 0, 0, 2, {0,1,0,0,0,0,0,0}, 0,0,0,-1,0,0,0, 1, ERR, 0, 1,0, 0 },
	/* ---- nl80211 failures ---- */
	{ "dump_command_message_null",       0, 1, 0, 2, {0,1,0,0,0,0,0,0}, 1,0,0,-1,0,0,0, 1, ERR, 0, 1,0, 0 },
	{ "dump_fails_after_stations",       0, 1, 0, 2, {0,1,0,0,0,0,0,0}, 0,0,-1,-1,0,0,0, 1, ERR, 0, 1,0, 0 },
	{ "query_command_message_null",      0, 1, 0, 2, {0,1,0,0,0,0,0,0}, 0,1,0,-1,0,0,0, 1, ERR, 0, 0,1, 0 },
	{ "query_fails_first_station",       0, 1, 0, 3, {0,1,2,0,0,0,0,0}, 0,0,0,0,0,0,0, 1, ERR, 0, 0,1, 0 },
	{ "query_fails_last_station",        0, 1, 0, 4, {0,1,2,3,0,0,0,0}, 0,0,0,3,0,0,0, 1, ERR, 0, 0,1, 0 },
	{ "query_fails_middle_station",      0, 1, 0, 4, {0,1,2,3,0,0,0,0}, 0,0,0,2,0,0,0, 1, ERR, 0, 0,1, 0 },
	/* ---- malformed MAC attribute in the dump: the station is skipped ---- */
	{ "dump_station_without_mac_skipped", 0, 1, 0, 3, {0,1,2,0,0,0,0,0}, 0,0,0,-1,0,0,2, 1, OK, -1, 0,0, 0 },
	/* ---- invalid inputs and failures that crash / leak the original (run last) ---- */
	{ "invalid_array_ptr_null_no_stations", 0, 1, 1, 0, NT,           0,0,0,-1,0,0,0, 1, ERR, 0, 1,0, 1 },
	{ "invalid_array_ptr_null_one_station", 0, 1, 1, 1, {0,0,0,0,0,0,0,0}, 0,0,0,-1,0,0,0, 1, ERR, 0, 1,0, 1 },
	{ "invalid_size_ptr_null_no_stations",  0, 1, 2, 0, NT,           0,0,0,-1,0,0,0, 1, ERR, 0, 1,0, 1 },
	{ "invalid_size_ptr_null_one_station",  0, 1, 2, 1, {0,0,0,0,0,0,0,0}, 0,0,0,-1,0,0,0, 1, ERR, 0, 1,0, 1 },
	{ "invalid_both_ptrs_null",             0, 1, 3, 1, {0,0,0,0,0,0,0,0}, 0,0,0,-1,0,0,0, 1, ERR, 0, 1,0, 1 },
	{ "invalid_calloc_fails_two_stations",  0, 1, 0, 2, {0,1,0,0,0,0,0,0}, 0,0,0,-1,1,0,0, 1, ERR, 0, 0,1, 1 },
	{ "invalid_realloc_fails_second_mac",   0, 1, 0, 3, {0,1,2,0,0,0,0,0}, 0,0,0,-1,0,2,0, 1, ERR, 0, 1,0, 1 },
	{ "invalid_dump_mac_attr_2_bytes",      0, 1, 0, 3, {0,1,2,0,0,0,0,0}, 0,0,0,-1,0,0,1, 1, OK, -1, 0,0, 1 },
	{ NULL }
};
