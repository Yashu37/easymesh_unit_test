/*
 * UNIT TEST (input constructor): construct_wifi_freq_to_op_class
 *
 * wifi_freq_to_op_class(freq) (platform/banana-pi) maps a frequency in MHz to its operating class through hostap's ieee80211_freq_to_channel_ext with
 * sec_channel 0 and chanwidth 0 (20 MHz).  Expected values follow IEEE 802.11 Annex E for 20 MHz channels: 2.4 GHz channels 1..13 -> 81, channel 14
 * -> 82; 5 GHz 36..48 -> 115, 52..64 -> 118, 100..144 -> 121, 149..161 -> 124, 165..177 -> 125; 6 GHz 5955..7115 -> 131, 5935 -> 136; 60 GHz 58320..69120
 * -> 180.  A frequency inside a known band but without a class (4.9 GHz, the unmapped 5 GHz gaps) returns 0, and a frequency in no band or one that is
 * not a channel centre returns RETURN_ERR (UINT 0xFFFFFFFF); the caller (OneWifi wifi_em.c) rejects both (op_class <= 0).  The function is pure: the
 * runner checks the return value, that nothing is logged on success and that the failure is logged with the frequency (log slot only).
 */
#include <limits.h>
#include "hwr_fco.h"

#define E ((unsigned)RETURN_ERR)

/* name, freq, calls, expected */
hwr_fco_case_t wifi_freq_to_op_class_suite[] = {
	/* 2.4 GHz */
	{ "ch1_2412",                 2412, 1, 81 },
	{ "ch6_2437",                 2437, 1, 81 },
	{ "ch13_2472",                2472, 1, 81 },
	{ "ch14_2484",                2484, 1, 82 },
	{ "2413_not_a_channel_centre", 2413, 1, E },
	{ "2411_below_band",          2411, 1, E },
	{ "2473_between_13_and_14",   2473, 1, E },
	{ "2485_above_ch14",          2485, 1, E },
	/* 4.9 GHz */
	{ "4900_known_band_no_class", 4900, 1, 0 },
	{ "4995_known_band_no_class", 4995, 1, 0 },
	{ "4902_not_a_channel_centre", 4902, 1, E },
	/* 5 GHz */
	{ "ch36_5180",               5180, 1, 115 },
	{ "ch40_5200",               5200, 1, 115 },
	{ "ch48_5240",               5240, 1, 115 },
	{ "5181_not_a_channel_centre", 5181, 1, E },
	{ "ch52_5260",               5260, 1, 118 },
	{ "ch64_5320",               5320, 1, 118 },
	{ "ch100_5500",              5500, 1, 121 },
	{ "ch144_5720",              5720, 1, 121 },
	{ "ch149_5745",              5745, 1, 124 },
	{ "ch161_5805",              5805, 1, 124 },
	{ "ch165_5825",              5825, 1, 125 },
	{ "ch177_5885",              5885, 1, 125 },
	{ "ch178_5890_no_class",     5890, 1, 0 },
	{ "5000_no_class",           5000, 1, 0 },
	{ "ch34_5170_no_class",      5170, 1, 0 },
	{ "ch50_5250_no_class",      5250, 1, 0 },
	{ "ch68_5340_no_class",      5340, 1, 0 },
	{ "ch145_5725_no_class",     5725, 1, 0 },
	{ "5899_not_a_channel_centre", 5899, 1, E },
	{ "5900_above_5ghz_band",    5900, 1, E },
	/* 6 GHz */
	{ "6ghz_ch2_5935",           5935, 1, 136 },
	{ "5950_gap",                5950, 1, E },
	{ "6ghz_ch1_5955",           5955, 1, 131 },
	{ "6ghz_ch5_5975",           5975, 1, 131 },
	{ "6ghz_ch233_7115",         7115, 1, 131 },
	{ "5951_not_a_channel_centre", 5951, 1, E },
	{ "7120_above_6ghz",         7120, 1, E },
	/* 60 GHz */
	{ "60ghz_ch1_58320",        58320, 1, 180 },
	{ "60ghz_ch2_60480",        60480, 1, 180 },
	{ "60ghz_ch6_69120",        69120, 1, 180 },
	{ "56160_below_60ghz_ch1",  56160, 1, E },
	{ "69121_above_60ghz",      69121, 1, E },
	/* out of range */
	{ "freq_0",                     0, 1, E },
	{ "freq_1",                     1, 1, E },
	{ "freq_int_max",         INT_MAX, 1, E },
	{ "freq_uint_max",       UINT_MAX, 1, E },
	{ "two_calls_5g",            5180, 2, 115 },
	{ "two_calls_error",         2413, 2, E },
	{ NULL, 0, 0, 0 }
};
