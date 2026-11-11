/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_setNeighborReports
 *
 * wifi_hal_setNeighborReports(apIndex, numNeighborReports, neighborReports).  Inputs crossed: neighborReports NULL; numNeighborReports 0 / 1 / 3 / 10; apIndex 0 / 1 / 3 / 4 (no interface); STA-mode interface;
 * neighbour report bit of radio_measurements[0] clear; hapd->conf NULL (hostapd not set up for the VAP); every optional sub-element present on its own (wide-band, TSF, country string, BSS candidate preference,
 * BSS termination, bearing, HT caps, HT operation, VHT caps, VHT operation, secondary channel offset, RM enabled caps, vendor specific, measurement pilot) and all together; target_ssid "ssid" / 32 non-NUL
 * characters / empty; hostapd_neighbor_set failing at the 1st / 2nd call; wpabuf_alloc failing at the 2nd.  The reports are an exact heap block of numNeighborReports entries.  Expected (CORRECT behaviour):
 * NULL reports or 0 reports -> WIFI_HAL_INVALID_ARGUMENTS; no interface / STA mode / hostapd not set up -> WIFI_HAL_ERROR with nothing changed; otherwise the neighbour database is cleared once, a clear
 * neighbour-report bit -> WIFI_HAL_ERROR with no entry installed; each report is installed as BSSID + SSID (at most 31 characters) + the element bytes (13 fixed bytes + the flagged sub-elements, little endian,
 * written inside its buffer); a failing set or allocation -> database cleared again and WIFI_HAL_ERROR; the lock is released and no buffer leaks.  Rows with last = 1 break the original: they run LAST.
 */
#include "hwr_wnr.h"
#include <limits.h>

/* name, apIndex, nrep_null, num, vap_sta, no_iface, conf_null, rm_enable, flags, ssid_kind, set_fail_at, alloc_fail_at, last */
hwr_wnr_case_t sg_wifi_hal_setNeighborReports_suite[] = {
	/* ---- arguments / interface ---- */
	{ "reports_null",          0, 1, 2, 0,0,0, 1, 0, 0, 0, 0, 0 },
	{ "num_0",                 0, 0, 0, 0,0,0, 1, 0, 0, 0, 0, 0 },
	{ "num_0_reports_null",    0, 1, 0, 0,0,0, 1, 0, 0, 0, 0, 0 },
	{ "apindex_4_no_interface",4, 0, 1, 0,0,0, 1, 0, 0, 0, 0, 0 },
	{ "interface_sta_mode",    1, 0, 1, 1,0,0, 1, 0, 0, 0, 0, 0 },
	{ "neighbor_report_bit_clear", 0, 0, 2, 0,0,0, 0, F_ALL, 0, 0, 0, 0 },
	/* ---- plain reports ---- */
	{ "one_report_no_subelements",   0, 0, 1, 0,0,0, 1, 0, 0, 0, 0, 0 },
	{ "three_reports",               2, 0, 3, 0,0,0, 1, 0, 0, 0, 0, 0 },
	{ "ten_reports",                 3, 0, 10, 0,0,0, 1, F_WIDE|F_PREF, 0, 0, 0, 0 },
	/* ---- each optional sub-element ---- */
	{ "sub_wide_bandwidth",   0, 0, 1, 0,0,0, 1, F_WIDE,  0, 0, 0, 0 },
	{ "sub_tsf",              0, 0, 1, 0,0,0, 1, F_TSF,   0, 0, 0, 0 },
	{ "sub_country_string",   0, 0, 1, 0,0,0, 1, F_CC,    0, 0, 0, 0 },
	{ "sub_candidate_pref",   0, 0, 1, 0,0,0, 1, F_PREF,  0, 0, 0, 0 },
	{ "sub_bss_termination",  0, 0, 1, 0,0,0, 1, F_TERM,  0, 0, 0, 0 },
	{ "sub_bearing",          0, 0, 1, 0,0,0, 1, F_BEAR,  0, 0, 0, 0 },
	{ "sub_ht_caps",          0, 0, 1, 0,0,0, 1, F_HTC,   0, 0, 0, 0 },
	{ "sub_ht_operation",     0, 0, 1, 0,0,0, 1, F_HTO,   0, 0, 0, 0 },
	{ "sub_vht_caps",         0, 0, 1, 0,0,0, 1, F_VHTC,  0, 0, 0, 0 },
	{ "sub_vht_operation",    0, 0, 1, 0,0,0, 1, F_VHTO,  0, 0, 0, 0 },
	{ "sub_secondary_offset", 0, 0, 1, 0,0,0, 1, F_SEC,   0, 0, 0, 0 },
	{ "sub_rm_enabled_caps",  0, 0, 1, 0,0,0, 1, F_RM,    0, 0, 0, 0 },
	{ "sub_vendor_specific",  0, 0, 1, 0,0,0, 1, F_VEND,  0, 0, 0, 0 },
	{ "sub_measurement_pilot",0, 0, 1, 0,0,0, 1, F_PILOT, 0, 0, 0, 0 },
	{ "all_subelements_one_report",   0, 0, 1, 0,0,0, 1, F_ALL, 0, 0, 0, 0 },
	{ "all_subelements_five_reports", 1, 0, 5, 0,0,0, 1, F_ALL, 0, 0, 0, 0 },
	/* ---- SSID ---- */
	{ "ssid_32_chars_no_nul", 0, 0, 2, 0,0,0, 1, F_WIDE, 1, 0, 0, 0 },
	{ "ssid_empty",           0, 0, 2, 0,0,0, 1, 0,      2, 0, 0, 0 },
	/* ---- failures ---- */
	{ "set_fails_first",      0, 0, 3, 0,0,0, 1, F_WIDE, 0, 1, 0, 0 },
	{ "set_fails_second",     0, 0, 3, 0,0,0, 1, F_ALL,  0, 2, 0, 0 },
	{ "alloc_fails_second",   0, 0, 3, 0,0,0, 1, F_TSF,  0, 0, 2, 0 },
	/* ---- the original dereferences hapd->conf for a log line before any check ---- */
	{ "hostapd_conf_null",    0, 0, 1, 0,0,1, 1, 0, 0, 0, 0, 1 },
	{ "hostapd_conf_null_five_reports", 2, 0, 5, 0,0,1, 1, F_ALL, 0, 0, 0, 1 },
	{ NULL }
};
