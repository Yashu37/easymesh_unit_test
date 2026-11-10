/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_getScanResults
 *
 * wifi_hal_getScanResults(index, channel, bss, num_bss).  Inputs crossed: channel / bss / num_bss NULL; radio index 0 / 1 / out of range (-1, 99) / no radio; the radio's interface map NULL / empty / without a STA
 * interface / with the STA interface first, second or last; channel band different from the radio band; channel number whose frequency lookup fails (-1), that gives frequency 0 (no filter) or a normal channel;
 * country US / CA / an unknown code; 0 .. 12 scan entries on the STA interface; which of them are on the requested frequency (none, all, a prefix, only the first, only the second, only the third, first and
 * third, the last of 8, alternate entries, all but the first), entries with frequency 0 that do not match; calloc failing.  The runner allocates nothing for the result (the function callocs it).  Expected
 * (CORRECT behaviour): any argument / lookup / band / frequency error -> -1 with *bss and *num_bss untouched, the scan mutex unlocked; calloc failure -> -1, *bss NULL, *num_bss 0; otherwise 0, *num_bss = the
 * number of entries on the frequency (all entries when the frequency is 0), *bss an array of exactly that many entries holding those scan entries in their original order.  Rows with last = 1 (a matching
 * entry that is not preceded only by matching ones) break the original: they run LAST.
 */
#include "hwr_wgs.h"

/* name, index, null_channel, null_bss, null_num, no_radio, imap_null, n_if, sta_pos, band_mismatch, ch_num, country, n_scan, match_mask, zero_mask, calloc_fail, last */
hwr_wgs_case_t sg_wifi_hal_getScanResults_suite[] = {
	/* ---- argument / lookup errors ---- */
	{ "channel_null",              0, 1,0,0, 0,0, 2, 1, 0, 36, 0, 3, 7, 0, 0, 0 },
	{ "bss_null",                  0, 0,1,0, 0,0, 2, 1, 0, 36, 0, 3, 7, 0, 0, 0 },
	{ "num_bss_null",              0, 0,0,1, 0,0, 2, 1, 0, 36, 0, 3, 7, 0, 0, 0 },
	{ "no_radio",                  0, 0,0,0, 1,0, 2, 1, 0, 36, 0, 3, 7, 0, 0, 0 },
	{ "index_minus1",     0xFFFFFFFFu, 0,0,0, 0,0, 2, 1, 0, 36, 0, 3, 7, 0, 0, 0 },
	{ "index_99",                 99, 0,0,0, 0,0, 2, 1, 0, 36, 0, 3, 7, 0, 0, 0 },
	{ "interface_map_null",        0, 0,0,0, 0,1, 2, 1, 0, 36, 0, 3, 7, 0, 0, 0 },
	{ "interface_map_empty",       0, 0,0,0, 0,0, 0,-1, 0, 36, 0, 3, 7, 0, 0, 0 },
	{ "only_ap_interfaces",        0, 0,0,0, 0,0, 3,-1, 0, 36, 0, 3, 7, 0, 0, 0 },
	{ "band_mismatch",             0, 0,0,0, 0,0, 2, 1, 1, 36, 0, 3, 7, 0, 0, 0 },
	{ "channel_freq_lookup_fails", 0, 0,0,0, 0,0, 2, 1, 0,  0, 0, 3, 7, 0, 0, 0 },
	/* ---- STA interface position / radio / country ---- */
	{ "sta_first",                 0, 0,0,0, 0,0, 3, 0, 0, 36, 0, 3, 7, 0, 0, 0 },
	{ "sta_second",                0, 0,0,0, 0,0, 3, 1, 0, 36, 0, 3, 7, 0, 0, 0 },
	{ "sta_last",                  0, 0,0,0, 0,0, 3, 2, 0, 36, 0, 3, 7, 0, 0, 0 },
	{ "radio_index_1",             1, 0,0,0, 0,0, 2, 1, 0, 36, 0, 3, 7, 0, 0, 0 },
	{ "country_ca",                0, 0,0,0, 0,0, 2, 1, 0, 36, 1, 3, 7, 0, 0, 0 },
	{ "country_unknown",           0, 0,0,0, 0,0, 2, 1, 0, 36, 2, 3, 7, 0, 0, 0 },
	/* ---- frequency 0: every entry is copied ---- */
	{ "freq0_no_entries",          0, 0,0,0, 0,0, 2, 1, 0,255, 0, 0, 0, 0, 0, 0 },
	{ "freq0_one_entry",           0, 0,0,0, 0,0, 2, 1, 0,255, 0, 1, 0, 0, 0, 0 },
	{ "freq0_three_entries",       0, 0,0,0, 0,0, 2, 1, 0,255, 0, 3, 2, 0, 0, 0 },
	{ "freq0_twelve_entries",      0, 0,0,0, 0,0, 2, 1, 0,255, 0,12, 0, 0, 0, 0 },
	/* ---- filtering by frequency, matches form a prefix (or there are none) ---- */
	{ "no_scan_entries",           0, 0,0,0, 0,0, 2, 1, 0, 36, 0, 0, 0, 0, 0, 0 },
	{ "one_entry_matches",         0, 0,0,0, 0,0, 2, 1, 0, 36, 0, 1, 1, 0, 0, 0 },
	{ "one_entry_no_match",        0, 0,0,0, 0,0, 2, 1, 0, 36, 0, 1, 0, 0, 0, 0 },
	{ "three_entries_none_match",  0, 0,0,0, 0,0, 2, 1, 0, 36, 0, 3, 0, 0, 0, 0 },
	{ "three_entries_all_match",   0, 0,0,0, 0,0, 2, 1, 0, 36, 0, 3, 7, 0, 0, 0 },
	{ "first_of_three_matches",    0, 0,0,0, 0,0, 2, 1, 0, 36, 0, 3, 1, 0, 0, 0 },
	{ "first_two_of_four_match",   0, 0,0,0, 0,0, 2, 1, 0, 36, 0, 4, 3, 0, 0, 0 },
	{ "prefix_of_eight",           0, 0,0,0, 0,0, 2, 1, 0, 36, 0, 8, 0x0f, 0, 0, 0 },
	{ "twelve_entries_all_match",  0, 0,0,0, 0,0, 2, 1, 0, 36, 0,12, 0xfff, 0, 0, 0 },
	{ "freq0_entries_do_not_match",0, 0,0,0, 0,0, 2, 1, 0, 36, 0, 3, 0, 7, 0, 0 },
	{ "calloc_fails_freq0",        0, 0,0,0, 0,0, 2, 1, 0,255, 0, 3, 0, 0, 1, 0 },
	{ "calloc_fails_filtered",     0, 0,0,0, 0,0, 2, 1, 0, 36, 0, 3, 7, 0, 1, 0 },
	/* ---- a matching entry preceded by a non-matching one: the original writes it at its scan index, past the calloc'd array ---- */
	{ "only_second_of_two",        0, 0,0,0, 0,0, 2, 1, 0, 36, 0, 2, 0x2, 0, 0, 1 },
	{ "only_third_of_three",       0, 0,0,0, 0,0, 2, 1, 0, 36, 0, 3, 0x4, 0, 0, 1 },
	{ "first_and_third_of_three",  0, 0,0,0, 0,0, 2, 1, 0, 36, 0, 3, 0x5, 0, 0, 1 },
	{ "only_last_of_eight",        0, 0,0,0, 0,0, 2, 1, 0, 36, 0, 8, 0x80, 0, 0, 1 },
	{ "alternate_entries_of_six",  0, 0,0,0, 0,0, 2, 1, 0, 36, 0, 6, 0x2a, 0, 0, 1 },
	{ "all_but_first_of_four",     0, 0,0,0, 0,0, 2, 1, 0, 36, 0, 4, 0xe, 0, 0, 1 },
	{ NULL, 0, 0,0,0, 0,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};
