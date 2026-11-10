/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_sm_deinit
 *
 * wifi_hal_sm_deinit(vap_index).  Inputs crossed: 1 / 2 / 3 interfaces; vap_index of a STA VAP with a wpa_sm (first, middle, last, only one), a STA VAP without a wpa_sm, a STA VAP whose wpa_sm
 * has no eapol, an AP VAP (its union holds hostapd data, which the function must not read), an unknown VAP (3, 15, -1, INT_MAX, no interface at all); repeated calls (the second one is a no-op
 * because the pointers were cleared); two STA VAPs deinitialised one after the other; a log slot nearly full.  Expected (correct behaviour): a STA VAP with a wpa_sm -> eapol_sm_deinit once with
 * its eapol, wpa_sm_deinit once with the wpa_sm, both pointers cleared, return 0; a STA VAP without a wpa_sm -> return 0, nothing deinitialised; an AP or unknown VAP -> return -1, nothing
 * deinitialised, no crash.  No row crashes the original.
 */
#include "hwr_wsd.h"
#include <limits.h>

/* name, vap_index, n_if, sta_mask, sm_mask, no_eapol, calls, prefill, last */
hwr_wsd_case_t sg_wifi_hal_sm_deinit_suite[] = {
	{ "sta_first_of_3",             0, 3, 7, 7, 0, 1,   0, 0 },
	{ "sta_middle_of_3",            1, 3, 7, 7, 0, 1,   0, 0 },
	{ "sta_last_of_3",              2, 3, 7, 7, 0, 1,   0, 0 },
	{ "sta_only_interface",         0, 1, 1, 1, 0, 1,   0, 0 },
	{ "sta_of_2",                   1, 2, 3, 3, 0, 1,   0, 0 },
	{ "sta_mixed_with_ap",          1, 3, 2, 2, 0, 1,   0, 0 },
	{ "sta_no_wpa_sm",              1, 3, 7, 5, 0, 1,   0, 0 },
	{ "sta_no_wpa_sm_only",         0, 1, 1, 0, 0, 1,   0, 0 },
	{ "sta_wpa_sm_no_eapol",        1, 3, 7, 7, 1, 1,   0, 0 },
	{ "sta_two_calls",              1, 3, 7, 7, 0, 2,   0, 0 },
	{ "sta_fifty_calls",            2, 3, 7, 7, 0, 50,  0, 0 },
	{ "sta_log_full",               1, 3, 7, 7, 0, 1, 255, 0 },
	{ "sta_two_calls_no_eapol",     0, 2, 3, 3, 1, 2,   0, 0 },
	/* AP VAP: not a STA VAP -> -1, its union is not read */
	{ "ap_first",                   0, 3, 6, 6, 0, 1,   0, 0 },
	{ "ap_last",                    2, 3, 3, 3, 0, 1,   0, 0 },
	{ "ap_only_interface",          0, 1, 0, 0, 0, 1,   0, 0 },
	{ "ap_two_calls",               1, 3, 5, 5, 0, 2,   0, 0 },
	/* unknown VAP -> -1 */
	{ "unknown_vap_3",              3, 3, 7, 7, 0, 1,   0, 0 },
	{ "unknown_vap_15",            15, 3, 7, 7, 0, 1,   0, 0 },
	{ "unknown_vap_minus1",        -1, 3, 7, 7, 0, 1,   0, 0 },
	{ "unknown_vap_int_max",  INT_MAX, 3, 7, 7, 0, 1,   0, 0 },
	{ "unknown_vap_int_min",  INT_MIN, 3, 7, 7, 0, 1,   0, 0 },
	{ "no_interfaces",              0, 0, 0, 0, 0, 1,   0, 0 },
	{ NULL, 0, 0, 0, 0, 0, 0, 0, 0 }
};
