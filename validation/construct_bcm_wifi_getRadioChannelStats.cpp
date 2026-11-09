/*
 * UNIT TEST (input constructor): construct_bcm_wifi_getRadioChannelStats
 *
 * wifi_getRadioChannelStats(radioIndex, array, array_size) (platform/broadcom) looks up the radio and its primary interface, sends the vendor
 * GET_SURVEY command and lets the real get_channel_stats_handler copy every survey entry (frequency -> channel via the real hostap conversion, 11
 * statistics) into the caller's array entry that has the same ch_number.  The kernel stub builds real libnl vendor messages.  The suite crosses: 1..4
 * survey entries, 2.4 / 5 / DFS / 6 GHz frequencies, entries with and without a matching array channel, a duplicate channel (last one wins), array
 * sizes 0 / 1 / 3 / 13 / 16, no entries, an unconvertible frequency (processing stops there), one survey attribute missing (processing stops), missing
 * vendor data / survey-info nest, unknown radio index, radio without interface, command message NULL, failing send (the handler has already run).
 * Rows named invalid_* run last: a NULL array with a positive size dereferences NULL (arr[i].ch_number), a NULL array with a negative size writes
 * arr[0] because the "not found" test is i == arr_size and a negative size never matches; and with a real array a negative size writes the first
 * entry although the caller said it has none (that row reports the wrong write, it does not abort).  The expected result is the safe one: WIFI_HAL_ERROR
 * with nothing written for a NULL array, nothing written for a size <= 0.
 * Row layout: see bgk_case_t in hwr_bgk.h.  Survey entry = { frequency, channel the code must derive (0 = none), attribute left out (0 = none) }.
 */
#include <limits.h>
#include "hwr_bgk.h"

#define OK   RETURN_OK
#define ERR  RETURN_ERR
#define E0 EN(0, 0, 0)
#define EN(f, c, o) { f, c, o }
/* default row: radio index 0 exists with an interface, array of 'size' entries starting at channel 'first' step 'step', no failures */
#define R(name, size, first, step, nent, e0, e1, e2, e3, ret, untouched) \
	{ name, 0, 1, 1, 1, size, first, step, nent, { e0, e1, e2, e3 }, 0, 0, 0, ret, untouched, 1, 0 }

#define F_NOISE 2
#define F_RADAR 3
#define F_UTIL  6
#define F_TOTAL 7
#define F_SELF  10
#define F_EXT   11
#define F_FREQ  1

bgk_case_t bcm_wifi_getRadioChannelStats_suite[] = {
	/* ---- 2.4 GHz updates ---- */
	R("one_entry_ch1",                   3, 1, 1, 1, EN(2412, 1, 0), E0, E0, E0, OK, 0),
	R("one_entry_ch2",                   3, 1, 1, 1, EN(2417, 2, 0), E0, E0, E0, OK, 0),
	R("three_entries_ch1_2_3",           3, 1, 1, 3, EN(2412, 1, 0), EN(2417, 2, 0), EN(2422, 3, 0), E0, OK, 0),
	R("four_entries_into_16_array",     16, 1, 1, 4, EN(2412, 1, 0), EN(2417, 2, 0), EN(2422, 3, 0), EN(2427, 4, 0), OK, 0),
	R("channel_13",                     13, 1, 1, 1, EN(2472, 13, 0), E0, E0, E0, OK, 0),
	R("array_size_1",                    1, 1, 1, 1, EN(2412, 1, 0), E0, E0, E0, OK, 0),
	R("duplicate_channel_last_wins",     3, 1, 1, 2, EN(2412, 1, 0), EN(2412, 1, 0), E0, E0, OK, 0),
	/* ---- other bands ---- */
	R("band_5g_ch36_ch40",               3, 36, 4, 2, EN(5180, 36, 0), EN(5200, 40, 0), E0, E0, OK, 0),
	R("band_5g_dfs_ch100",               2, 100, 4, 1, EN(5500, 100, 0), E0, E0, E0, OK, 0),
	R("band_6g_ch1",                     3, 1, 1, 1, EN(5955, 1, 0), E0, E0, E0, OK, 0),
	/* ---- entries without a matching array channel / empty ---- */
	R("entry_channel_not_in_array",      3, 1, 1, 1, EN(2437, 6, 0), E0, E0, E0, OK, 1),
	R("one_match_one_not_in_array",      3, 1, 1, 2, EN(2412, 1, 0), EN(2437, 6, 0), E0, E0, OK, 0),
	R("no_survey_entries",               3, 1, 1, 0, E0, E0, E0, E0, OK, 1),
	R("array_size_0_with_entry",         0, 1, 1, 1, EN(2412, 1, 0), E0, E0, E0, OK, 1),
	/* ---- malformed survey data: the handler stops, the call still reports success ---- */
	R("unknown_frequency_first",         3, 1, 1, 2, EN(1234, 0, 0), EN(2412, 1, 0), E0, E0, OK, 1),
	R("unknown_frequency_after_valid",   3, 1, 1, 3, EN(2412, 1, 0), EN(1234, 0, 0), EN(2417, 2, 0), E0, OK, 0),
	R("missing_noise_attribute",         3, 1, 1, 1, EN(2412, 0, F_NOISE), E0, E0, E0, OK, 1),
	R("missing_radar_noise_attribute",   3, 1, 1, 1, EN(2412, 0, F_RADAR), E0, E0, E0, OK, 1),
	R("missing_chan_util_attribute",     3, 1, 1, 1, EN(2412, 0, F_UTIL), E0, E0, E0, OK, 1),
	R("missing_time_active_attribute",   3, 1, 1, 1, EN(2412, 0, F_TOTAL), E0, E0, E0, OK, 1),
	R("missing_busy_rx_self_attribute",  3, 1, 1, 1, EN(2412, 0, F_SELF), E0, E0, E0, OK, 1),
	R("missing_ext_busy_attribute",      3, 1, 1, 1, EN(2412, 0, F_EXT), E0, E0, E0, OK, 1),
	R("missing_frequency_in_2nd_entry",  3, 1, 1, 2, EN(2412, 1, 0), EN(2417, 0, F_FREQ), E0, E0, OK, 0),
	{ "vendor_data_missing",   0, 1, 1, 1, 3, 1, 1, 1, { { 2412, 0, 0 }, E0, E0, E0 }, 0, 0, 1, OK, 1, 1, 0 },
	{ "survey_info_missing",   0, 1, 1, 1, 3, 1, 1, 1, { { 2412, 0, 0 }, E0, E0, E0 }, 0, 0, 2, OK, 1, 1, 0 },
	/* ---- lookups and command failures ---- */
	{ "radio_index_unknown",   7, 1, 1, 1, 3, 1, 1, 1, { { 2412, 1, 0 }, E0, E0, E0 }, 0, 0, 0, ERR, 1, 1, 0 },
	{ "radio_index_negative",  -1, 0, 1, 1, 3, 1, 1, 1, { { 2412, 1, 0 }, E0, E0, E0 }, 0, 0, 0, ERR, 1, 1, 0 },
	{ "radio_index_int_max",   INT_MAX, 1, 1, 1, 3, 1, 1, 1, { { 2412, 1, 0 }, E0, E0, E0 }, 0, 0, 0, ERR, 1, 1, 0 },
	{ "no_radio_at_all",       0, 0, 1, 1, 3, 1, 1, 1, { { 2412, 1, 0 }, E0, E0, E0 }, 0, 0, 0, ERR, 1, 1, 0 },
	{ "radio_without_interface", 0, 1, 0, 1, 3, 1, 1, 1, { { 2412, 1, 0 }, E0, E0, E0 }, 0, 0, 0, ERR, 1, 1, 0 },
	{ "command_message_null",  0, 1, 1, 1, 3, 1, 1, 1, { { 2412, 1, 0 }, E0, E0, E0 }, 1, 0, 0, ERR, 1, 1, 0 },
	{ "send_fails_after_handler", 0, 1, 1, 1, 3, 1, 1, 1, { { 2412, 1, 0 }, E0, E0, E0 }, 0, -1, 0, ERR, 0, 1, 0 },
	{ "two_calls_same_result", 0, 1, 1, 1, 3, 1, 1, 2, { { 2412, 1, 0 }, { 2417, 2, 0 }, E0, E0 }, 0, 0, 0, OK, 0, 2, 0 },
	/* ---- NULL array without a loop iteration: no dereference ---- */
	{ "array_null_size_0",     0, 1, 1, 0, 0, 1, 1, 1, { { 2412, 1, 0 }, E0, E0, E0 }, 0, 0, 0, OK, 1, 1, 0 },
	{ "array_null_no_entries", 0, 1, 1, 0, 3, 1, 1, 0, { E0, E0, E0, E0 }, 0, 0, 0, OK, 1, 1, 0 },
	/* ---- invalid inputs that corrupt / crash the original (run last) ---- */
	{ "invalid_negative_size_writes_arr0", 0, 1, 1, 1, -1, 99, 1, 1, { { 2412, 1, 0 }, E0, E0, E0 }, 0, 0, 0, OK, 1, 1, 1 },
	{ "invalid_array_null_size_3",         0, 1, 1, 0, 3, 1, 1, 1, { { 2412, 1, 0 }, E0, E0, E0 }, 0, 0, 0, ERR, 1, 1, 1 },
	{ "invalid_array_null_size_negative",  0, 1, 1, 0, -1, 1, 1, 1, { { 2412, 1, 0 }, E0, E0, E0 }, 0, 0, 0, ERR, 1, 1, 1 },
	{ NULL }
};
