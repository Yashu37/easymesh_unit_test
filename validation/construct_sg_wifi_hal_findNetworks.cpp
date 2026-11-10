/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_findNetworks
 *
 * wifi_hal_findNetworks(ap_index, channel, bss_array, num_bss).  Inputs crossed: NULL channel / bss_array / num_bss; 1 / 2 / 3 interfaces; ap_index of a STA VAP (first, middle, last), of an AP VAP
 * (its union holds hostapd data), of an unknown VAP (3, 15, -1, INT_MAX, INT_MIN, no interface at all); channel filter 0 (every entry) / a channel present once / several times / absent / 14 / 165 / 233
 * / 255 / 256 / negative / INT_MAX; scan lists of 0 .. 6 entries on the 2.4 / 5 / 6 GHz bands, with unknown frequencies (0, 1, 9999, UINT_MAX); calloc failing; a log slot nearly full.  Expected
 * (correct behaviour): a NULL argument, an unknown VAP or an AP VAP -> -1 with the outputs untouched; otherwise 0, *num_bss = number of entries on the channel (all for channel 0), *bss_array holds
 * copies of exactly those entries in list order, the scan mutex is released, no allocation is left once the caller has freed the array; calloc failing -> -1, *bss_array NULL, *num_bss 0.  No row
 * crashes the original.
 */
#include "hwr_wfn.h"
#include <limits.h>

/* name, vap_index, n_if, sta_mask, chan, null_chan, null_arr, null_num, n_scan, freq[6], calloc_fail, prefill, last */
hwr_wfn_case_t sg_wifi_hal_findNetworks_suite[] = {
	/* ---- all entries (channel 0) ---- */
	{ "all_three_entries",          0, 3, 7,   0, 0,0,0, 3, {2412, 5180, 5955},        0,   0, 0 },
	{ "all_six_entries",            1, 3, 7,   0, 0,0,0, 6, {2412, 2437, 5180, 5240, 5955, 6115}, 0, 0, 0 },
	{ "all_one_entry",              2, 3, 7,   0, 0,0,0, 1, {5180},                    0,   0, 0 },
	{ "all_empty_list",             1, 3, 7,   0, 0,0,0, 0, {0},                       0,   0, 0 },
	{ "all_unknown_freqs",          1, 3, 7,   0, 0,0,0, 4, {0, 1, 9999, UINT_MAX},    0,   0, 0 },
	{ "all_only_interface",         0, 1, 1,   0, 0,0,0, 2, {2412, 5180},              0,   0, 0 },
	{ "all_log_full",               1, 3, 7,   0, 0,0,0, 2, {2412, 5180},              0, 255, 0 },
	/* ---- channel filter ---- */
	{ "chan_one_match",             1, 3, 7,   6, 0,0,0, 4, {2412, 2437, 5180, 5955},  0,   0, 0 },
	{ "chan_several_match",         1, 3, 7,  36, 0,0,0, 5, {5180, 2412, 5180, 5180, 5240}, 0, 0, 0 },
	{ "chan_no_match",              1, 3, 7,  11, 0,0,0, 3, {2412, 2437, 5180},        0,   0, 0 },
	{ "chan_empty_list",            1, 3, 7,   6, 0,0,0, 0, {0},                       0,   0, 0 },
	{ "chan_14",                    1, 3, 7,  14, 0,0,0, 3, {2484, 2412, 2484},        0,   0, 0 },
	{ "chan_165",                   1, 3, 7, 165, 0,0,0, 2, {5825, 5180},              0,   0, 0 },
	{ "chan_233_6ghz",              1, 3, 7, 233, 0,0,0, 2, {7115, 5955},              0,   0, 0 },
	{ "chan_255",                   1, 3, 7, 255, 0,0,0, 3, {2412, 5180, 5955},        0,   0, 0 },
	{ "chan_256_never_matches",     1, 3, 7, 256, 0,0,0, 3, {2412, 5180, 5955},        0,   0, 0 },
	{ "chan_negative",              1, 3, 7,  -1, 0,0,0, 3, {2412, 5180, 5955},        0,   0, 0 },
	{ "chan_int_max",               1, 3, 7, INT_MAX, 0,0,0, 3, {2412, 5180, 5955},    0,   0, 0 },
	{ "chan_unknown_freq_not_zero", 1, 3, 7,   1, 0,0,0, 3, {0, 1, UINT_MAX},          0,   0, 0 },
	{ "chan_same_chan_other_bands", 1, 3, 7,   1, 0,0,0, 2, {2412, 5955},              0,   0, 0 },
	{ "chan_first_of_3_interfaces", 0, 3, 7,  36, 0,0,0, 3, {5180, 5200, 5180},        0,   0, 0 },
	{ "chan_last_of_3_interfaces",  2, 3, 7,  36, 0,0,0, 3, {5180, 5200, 5180},        0,   0, 0 },
	/* ---- allocation failure ---- */
	{ "calloc_fails_all",           1, 3, 7,   0, 0,0,0, 3, {2412, 5180, 5955},        1,   0, 0 },
	{ "calloc_fails_channel",       1, 3, 7,  36, 0,0,0, 3, {5180, 5180, 5955},        1,   0, 0 },
	/* ---- NULL arguments ---- */
	{ "null_channel",               1, 3, 7,   0, 1,0,0, 3, {2412, 5180, 5955},        0,   0, 0 },
	{ "null_bss_array",             1, 3, 7,   0, 0,1,0, 3, {2412, 5180, 5955},        0,   0, 0 },
	{ "null_num_bss",               1, 3, 7,   0, 0,0,1, 3, {2412, 5180, 5955},        0,   0, 0 },
	{ "all_arguments_null",         1, 3, 7,   0, 1,1,1, 3, {2412, 5180, 5955},        0,   0, 0 },
	{ "null_channel_unknown_vap",   9, 3, 7,   0, 1,0,0, 0, {0},                       0,   0, 0 },
	/* ---- AP VAP / unknown VAP ---- */
	{ "ap_vap_first",               0, 3, 6,   0, 0,0,0, 3, {2412, 5180, 5955},        0,   0, 0 },
	{ "ap_vap_last_channel",        2, 3, 3,  36, 0,0,0, 3, {5180, 5180, 5955},        0,   0, 0 },
	{ "unknown_vap_3",              3, 3, 7,   0, 0,0,0, 3, {2412, 5180, 5955},        0,   0, 0 },
	{ "unknown_vap_15",            15, 3, 7,   0, 0,0,0, 3, {2412, 5180, 5955},        0,   0, 0 },
	{ "unknown_vap_minus1",        -1, 3, 7,   0, 0,0,0, 3, {2412, 5180, 5955},        0,   0, 0 },
	{ "unknown_vap_int_max",  INT_MAX, 3, 7,   0, 0,0,0, 3, {2412, 5180, 5955},        0,   0, 0 },
	{ "unknown_vap_int_min",  INT_MIN, 3, 7,   0, 0,0,0, 3, {2412, 5180, 5955},        0,   0, 0 },
	{ "no_interfaces",              0, 0, 0,   0, 0,0,0, 0, {0},                       0,   0, 0 },
	{ NULL, 0, 0, 0, 0, 0, 0, 0, 0, {0}, 0, 0, 0 }
};
