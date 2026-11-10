/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_disconnect
 *
 * wifi_hal_disconnect(ap_index).  Inputs crossed: 1 / 2 / 3 interfaces; ap_index of a STA VAP (first, middle, last, only one), of an AP VAP (its union holds hostapd data, which the function
 * must not read), of an unknown VAP (3, 15, -1, INT_MAX, INT_MIN, no interface at all); nl80211_disconnect_sta succeeding / failing with -1 / another non-zero value; repeated calls; a log slot
 * nearly full.  Expected (correct behaviour): a STA VAP -> nl80211_disconnect_sta once per call with that VAP's interface, return 0 (-1 when it fails); an AP VAP -> -4 and no disconnect; an
 * unknown VAP -> -1 and no disconnect; no crash.  No row crashes the original.
 */
#include "hwr_wdc.h"
#include <limits.h>

/* name, vap_index, n_if, sta_mask, disc_ret, calls, prefill, last */
hwr_wdc_case_t sg_wifi_hal_disconnect_suite[] = {
	{ "sta_first_of_3",            0, 3, 7,  0,  1,   0, 0 },
	{ "sta_middle_of_3",           1, 3, 7,  0,  1,   0, 0 },
	{ "sta_last_of_3",             2, 3, 7,  0,  1,   0, 0 },
	{ "sta_only_interface",        0, 1, 1,  0,  1,   0, 0 },
	{ "sta_of_2",                  1, 2, 3,  0,  1,   0, 0 },
	{ "sta_mixed_with_ap",         1, 3, 2,  0,  1,   0, 0 },
	{ "sta_disconnect_fails_m1",   1, 3, 7, -1,  1,   0, 0 },
	{ "sta_disconnect_fails_other",1, 3, 7,  5,  1,   0, 0 },
	{ "sta_disconnect_fails_neg",  1, 3, 7, -95, 1,  0, 0 },
	{ "sta_two_calls",             1, 3, 7,  0,  2,   0, 0 },
	{ "sta_fifty_calls",           2, 3, 7,  0, 50,   0, 0 },
	{ "sta_log_full",              1, 3, 7,  0,  1, 255, 0 },
	{ "sta_two_calls_failing",     1, 3, 7, -1,  2,   0, 0 },
	/* AP VAP: not a STA VAP -> -4, its union is not read */
	{ "ap_first",                  0, 3, 6,  0,  1,   0, 0 },
	{ "ap_last",                   2, 3, 3,  0,  1,   0, 0 },
	{ "ap_only_interface",         0, 1, 0,  0,  1,   0, 0 },
	{ "ap_two_calls",              1, 3, 5,  0,  2,   0, 0 },
	{ "ap_with_failing_driver",    1, 3, 5, -1,  1,   0, 0 },
	/* unknown VAP -> -1 */
	{ "unknown_vap_3",             3, 3, 7,  0,  1,   0, 0 },
	{ "unknown_vap_15",           15, 3, 7,  0,  1,   0, 0 },
	{ "unknown_vap_minus1",       -1, 3, 7,  0,  1,   0, 0 },
	{ "unknown_vap_int_max", INT_MAX, 3, 7,  0,  1,   0, 0 },
	{ "unknown_vap_int_min", INT_MIN, 3, 7,  0,  1,   0, 0 },
	{ "no_interfaces",             0, 0, 0,  0,  1,   0, 0 },
	{ NULL, 0, 0, 0, 0, 0, 0, 0 }
};
