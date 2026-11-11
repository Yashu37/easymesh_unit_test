/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_setRMBeaconRequest
 *
 * wifi_hal_setRMBeaconRequest(apIndex, peer_mac, in_req, out_DialogToken).  Inputs crossed: peer_mac / in_req / out_DialogToken NULL; apIndex 0 / 1 / 3 / 4 (no interface) / UINT_MAX; STA-mode interface;
 * channel 0 / 255 / 36 / 233 / 234 (invalid) with opClass 115 / 0 / 99; mode 0 / 2 / 3 / 255; SSID absent / "abc" / 32 non-NUL characters / empty; beacon reporting, reporting detail present / absent; channel report
 * absent / empty / 1 / 63 / 64 channels (zero-terminated below 64, full at 64) with channel 255; requested element IDs; wide-band channel with width 0 / 3 / 4 / 255 and centre segments valid / invalid;
 * wifi_rrm_send_beacon_req returning -1 / 0 / 5 / 255 / 300.  in_req and out_DialogToken are exact heap blocks.  Expected (CORRECT behaviour): NULL pointers -> WIFI_HAL_INVALID_ARGUMENTS; no interface /
 * STA mode, an invalid channel / op class pair, mode > 2, a wide-band width > 3, or an empty channel report with channel 255 -> WIFI_HAL_ERROR with nothing sent; otherwise one request is sent for the peer with
 * all the fields (SSID at most 31 characters, optional condition / threshold / detail, the number of non-zero channels at most 64, element list of 8, wide-band width and the centre segments that are valid) and
 * *out_DialogToken = the returned token (low 8 bits); a negative token -> WIFI_HAL_ERROR with *out_DialogToken unchanged; the lock is released and nothing is read from fields whose Present flag is off.
 * No crash case is expected.
 */
#include "hwr_wrb.h"
#include <limits.h>

/* name, apIndex, peer_null, req_null, out_null, no_iface, vap_sta, opClass, channel, mode, ssid_kind, rep, det, chrep_n, elem, wide, bw, seg0, seg1, send_ret, last */
hwr_wrb_case_t sg_wifi_hal_setRMBeaconRequest_suite[] = {
	/* ---- arguments / interface ---- */
	{ "peer_null",             0, 1,0,0, 0,0, 115, 36, 0, -1, 0,0, -1, 0, 0,0,0,0, 1, 0 },
	{ "request_null",          0, 0,1,0, 0,0, 115, 36, 0, -1, 0,0, -1, 0, 0,0,0,0, 1, 0 },
	{ "out_token_null",        0, 0,0,1, 0,0, 115, 36, 0, -1, 0,0, -1, 0, 0,0,0,0, 1, 0 },
	{ "all_three_null",        0, 1,1,1, 0,0, 115, 36, 0, -1, 0,0, -1, 0, 0,0,0,0, 1, 0 },
	{ "apindex_4_no_interface",4, 0,0,0, 0,0, 115, 36, 0, -1, 0,0, -1, 0, 0,0,0,0, 1, 0 },
	{ "apindex_uint_max", UINT_MAX, 0,0,0, 0,0, 115, 36, 0, -1, 0,0, -1, 0, 0,0,0,0, 1, 0 },
	{ "interface_sta_mode",    1, 0,0,0, 0,1, 115, 36, 0, -1, 0,0, -1, 0, 0,0,0,0, 1, 0 },
	/* ---- channel / op class / mode ---- */
	{ "channel_36_ok",         0, 0,0,0, 0,0, 115, 36, 0, -1, 0,0, -1, 0, 0,0,0,0, 1, 0 },
	{ "channel_0_not_checked", 0, 0,0,0, 0,0,   0,  0, 0, -1, 0,0, -1, 0, 0,0,0,0, 1, 0 },
	{ "channel_255_not_checked",0,0,0,0, 0,0,   0,255, 0, -1, 0,0, -1, 0, 0,0,0,0, 1, 0 },
	{ "channel_233_ok",        0, 0,0,0, 0,0, 125,233, 0, -1, 0,0, -1, 0, 0,0,0,0, 1, 0 },
	{ "channel_234_invalid",   0, 0,0,0, 0,0, 115,234, 0, -1, 0,0, -1, 0, 0,0,0,0, 1, 0 },
	{ "opclass_0_invalid",     0, 0,0,0, 0,0,   0, 36, 0, -1, 0,0, -1, 0, 0,0,0,0, 1, 0 },
	{ "opclass_99_invalid",    0, 0,0,0, 0,0,  99, 36, 0, -1, 0,0, -1, 0, 0,0,0,0, 1, 0 },
	{ "mode_2_ok",             0, 0,0,0, 0,0, 115, 36, 2, -1, 0,0, -1, 0, 0,0,0,0, 1, 0 },
	{ "mode_3_invalid",        0, 0,0,0, 0,0, 115, 36, 3, -1, 0,0, -1, 0, 0,0,0,0, 1, 0 },
	{ "mode_255_invalid",      0, 0,0,0, 0,0, 115, 36,255, -1, 0,0, -1, 0, 0,0,0,0, 1, 0 },
	/* ---- optional fields ---- */
	{ "ssid_abc",              0, 0,0,0, 0,0, 115, 36, 0, 0, 0,0, -1, 0, 0,0,0,0, 1, 0 },
	{ "ssid_32_chars_no_nul",  0, 0,0,0, 0,0, 115, 36, 0, 1, 0,0, -1, 0, 0,0,0,0, 1, 0 },
	{ "ssid_empty",            0, 0,0,0, 0,0, 115, 36, 0, 2, 0,0, -1, 0, 0,0,0,0, 1, 0 },
	{ "beacon_reporting",      0, 0,0,0, 0,0, 115, 36, 0, -1, 1,0, -1, 0, 0,0,0,0, 1, 0 },
	{ "reporting_detail",      0, 0,0,0, 0,0, 115, 36, 0, -1, 0,1, -1, 0, 0,0,0,0, 1, 0 },
	{ "requested_elements",    0, 0,0,0, 0,0, 115, 36, 0, -1, 0,0, -1, 1, 0,0,0,0, 1, 0 },
	/* ---- channel report ---- */
	{ "chrep_1_channel",       0, 0,0,0, 0,0, 115, 36, 0, -1, 0,0,  1, 0, 0,0,0,0, 1, 0 },
	{ "chrep_63_channels",     0, 0,0,0, 0,0, 115, 36, 0, -1, 0,0, 63, 0, 0,0,0,0, 1, 0 },
	{ "chrep_64_channels_full",0, 0,0,0, 0,0, 115, 36, 0, -1, 0,0, 64, 0, 0,0,0,0, 1, 0 },
	{ "chrep_empty_channel_36",0, 0,0,0, 0,0, 115, 36, 0, -1, 0,0,  0, 0, 0,0,0,0, 1, 0 },
	{ "chrep_empty_channel_255",0,0,0,0, 0,0,   0,255, 0, -1, 0,0,  0, 0, 0,0,0,0, 1, 0 },
	{ "chrep_64_channel_255",  0, 0,0,0, 0,0,   0,255, 0, -1, 0,0, 64, 0, 0,0,0,0, 1, 0 },
	/* ---- wide-band channel ---- */
	{ "wide_80mhz_valid_segments", 0, 0,0,0, 0,0, 115, 36, 0, -1, 0,0, -1, 0, 1, 1, 42, 58, 1, 0 },
	{ "wide_width_3_ok",       0, 0,0,0, 0,0, 115, 36, 0, -1, 0,0, -1, 0, 1, 3, 42, 58, 1, 0 },
	{ "wide_width_4_invalid",  0, 0,0,0, 0,0, 115, 36, 0, -1, 0,0, -1, 0, 1, 4, 42, 58, 1, 0 },
	{ "wide_width_255_invalid",0, 0,0,0, 0,0, 115, 36, 0, -1, 0,0, -1, 0, 1,255, 42, 58, 1, 0 },
	{ "wide_segment0_invalid", 0, 0,0,0, 0,0, 115, 36, 0, -1, 0,0, -1, 0, 1, 1,  0, 58, 1, 0 },
	{ "wide_segment1_invalid", 0, 0,0,0, 0,0, 115, 36, 0, -1, 0,0, -1, 0, 1, 1, 42,  0, 1, 0 },
	{ "wide_both_segments_invalid", 0, 0,0,0, 0,0, 115, 36, 0, -1, 0,0, -1, 0, 1, 0,  0,250, 1, 0 },
	/* ---- send result ---- */
	{ "send_fails",            0, 0,0,0, 0,0, 115, 36, 0, -1, 0,0, -1, 0, 0,0,0,0, -1, 0 },
	{ "send_token_0",          0, 0,0,0, 0,0, 115, 36, 0, -1, 0,0, -1, 0, 0,0,0,0, 0, 0 },
	{ "send_token_255",        0, 0,0,0, 0,0, 115, 36, 0, -1, 0,0, -1, 0, 0,0,0,0, 255, 0 },
	{ "send_token_300_low_8_bits", 0, 0,0,0, 0,0, 115, 36, 0, -1, 0,0, -1, 0, 0,0,0,0, 300, 0 },
	{ "everything_present",    1, 0,0,0, 0,0, 115, 36, 1, 0, 1,1, 5, 1, 1, 2, 42, 58, 7, 0 },
	{ NULL }
};
