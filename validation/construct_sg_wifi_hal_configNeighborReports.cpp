/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_configNeighborReports
 *
 * wifi_hal_configNeighborReports(apIndex, enable, auto_resp).  Inputs crossed: apIndex 0 / 1 / 3 / 4 (no interface) / 100 / UINT_MAX; interface in STA mode; enable 0 / 1; auto_resp 0 / 1; the previous
 * conf->radio_measurements[0] 0x00 / 0x02 / 0xFF / 0xFD / 0x7D; the previous activation / auto-response state set / clear.  Expected (CORRECT behaviour): no interface or STA mode -> RETURN_ERR and nothing
 * changed; otherwise RETURN_OK, vap_info nbrReportActivated = bssTransitionActivated = enable, conf->bss_transition = enable, the neighbour-report bit (0x02) of radio_measurements[0] set when enabled and
 * cleared otherwise with the other seven bits untouched, wnm_bss_trans_query_auto_resp = auto_resp, radio_measurements[1..4] and the other conf fields untouched, the lock released.  No crash expected.
 */
#include "hwr_wcn.h"
#include <limits.h>

/* name, apIndex, vap_sta, enable, auto_resp, rm0, old_enable, old_auto, last */
hwr_wcn_case_t sg_wifi_hal_configNeighborReports_suite[] = {
	/* ---- interface ---- */
	{ "apindex_4_no_interface",    4, 0, 1, 1, 0x00, 0, 0, 0 },
	{ "apindex_100_no_interface", 100, 0, 1, 1, 0x00, 0, 0, 0 },
	{ "apindex_uint_max",   UINT_MAX, 0, 0, 0, 0x02, 1, 1, 0 },
	{ "interface_sta_mode",        1, 1, 1, 1, 0x00, 0, 0, 0 },
	{ "interface_sta_mode_disable",2, 1, 0, 0, 0x02, 1, 1, 0 },
	/* ---- enable ---- */
	{ "enable_apindex_0",          0, 0, 1, 0, 0x00, 0, 0, 0 },
	{ "enable_apindex_3",          3, 0, 1, 1, 0x00, 0, 0, 0 },
	{ "enable_already_set",        1, 0, 1, 1, 0x02, 1, 1, 0 },
	{ "enable_keeps_other_bits",   1, 0, 1, 0, 0xFD, 0, 0, 0 },
	{ "enable_all_bits_set",       2, 0, 1, 1, 0xFF, 1, 1, 0 },
	/* ---- disable ---- */
	{ "disable_clears_bit",        0, 0, 0, 0, 0x02, 1, 1, 0 },
	{ "disable_keeps_other_bits",  1, 0, 0, 1, 0xFF, 1, 0, 0 },
	{ "disable_bit_already_clear", 1, 0, 0, 0, 0x00, 0, 0, 0 },
	{ "disable_other_bits_only",   2, 0, 0, 1, 0x7D, 0, 1, 0 },
	/* ---- auto_resp independent of enable ---- */
	{ "enable_auto_resp_off",      3, 0, 1, 0, 0x00, 0, 1, 0 },
	{ "disable_auto_resp_on",      3, 0, 0, 1, 0x02, 1, 0, 0 },
	{ "toggle_from_enabled_to_disabled", 0, 0, 0, 0, 0xFF, 1, 1, 0 },
	{ "toggle_from_disabled_to_enabled", 0, 0, 1, 1, 0xFD, 0, 0, 0 },
	{ NULL }
};
