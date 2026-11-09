/*
 * UNIT TEST (input constructor): construct_wifi_sendActionFrameExt
 *
 * wifi_sendActionFrameExt(apIndex, MacAddr, frequency, wait, frame, len) (platform/banana-pi) forwards to wifi_hal_send_mgmt_frame (src/wifi_hal.c:4775):
 * it allocates 24 + len bytes, copies frame to offset 24, fills the 802.11 header (frame control = management / action, addr1 = MacAddr, addr2 = the
 * interface MAC, addr3 = broadcast), looks the interface up by apIndex and hands the buffer to wifi_drv_send_mlme (freq, wait); the result is
 * mapped to WIFI_HAL_SUCCESS / WIFI_HAL_ERROR.  The suite crosses: the interface lookup (found / missing / another vap index, negative / INT_MIN /
 * INT_MAX index), the frame length (1, 2, 10, 24, 25, 100, 1500, 4096, 65535), frequency and wait values (0 / typical / UINT_MAX), the return value of
 * wifi_drv_send_mlme (0 / -1 / 1 / 5 / INT_MIN), an allocation failure, and the invalid inputs: frame NULL with len > 0, MacAddr NULL, len == 0
 * (an action frame without even the category byte, which the send path reads: wifi_hal_nl80211.c:13954).  Rows with crash = 1 crash the original
 * function and run last.  The correct result for them is WIFI_HAL_ERROR and no frame handed to the driver.
 */
#include <limits.h>
#include "hwr_sae.h"

#define SUC WIFI_HAL_SUCCESS
#define ERR WIFI_HAL_ERROR

/* name, ap_index, has_iface, frame_mode, len, mac_mode, freq, wait, mlme_rc, fail_alloc, expected_ret, exp_calls, crash */
hwr_sae_case_t wifi_sendActionFrameExt_suite[] = {
	/* ---- normal rows ---- */
	{ "basic_len_10",                      0, 1, 1,    10, 1, 2412,       0, 0, 0, SUC, 1, 0 },
	{ "len_1",                             0, 1, 1,     1, 1, 2412,       0, 0, 0, SUC, 1, 0 },
	{ "len_2",                             0, 1, 1,     2, 1, 2412,       0, 0, 0, SUC, 1, 0 },
	{ "len_24",                            0, 1, 1,    24, 1, 2412,       0, 0, 0, SUC, 1, 0 },
	{ "len_25",                            0, 1, 1,    25, 1, 2412,       0, 0, 0, SUC, 1, 0 },
	{ "len_100",                           0, 1, 1,   100, 1, 5180,       0, 0, 0, SUC, 1, 0 },
	{ "len_1500",                          0, 1, 1,  1500, 1, 5180,       0, 0, 0, SUC, 1, 0 },
	{ "len_4096",                          0, 1, 1,  4096, 1, 5180,       0, 0, 0, SUC, 1, 0 },
	{ "len_65535",                         0, 1, 1, 65535, 1, 5180,       0, 0, 0, SUC, 1, 0 },
	{ "freq_0",                            0, 1, 1,    10, 1,    0,       0, 0, 0, SUC, 1, 0 },
	{ "freq_5955",                         0, 1, 1,    10, 1, 5955,       0, 0, 0, SUC, 1, 0 },
	{ "freq_max",                          0, 1, 1,    10, 1, UINT_MAX,   0, 0, 0, SUC, 1, 0 },
	{ "wait_50",                           0, 1, 1,    10, 1, 2412,      50, 0, 0, SUC, 1, 0 },
	{ "wait_max",                          0, 1, 1,    10, 1, 2412, UINT_MAX, 0, 0, SUC, 1, 0 },
	{ "freq_and_wait_max",                 0, 1, 1,    10, 1, UINT_MAX, UINT_MAX, 0, 0, SUC, 1, 0 },
	{ "ap_index_15",                      15, 1, 1,    10, 1, 2412,       0, 0, 0, SUC, 1, 0 },
	{ "ap_index_negative_iface_matches",  -1, 1, 1,    10, 1, 2412,       0, 0, 0, SUC, 1, 0 },
	{ "ap_index_int_max",            INT_MAX, 1, 1,    10, 1, 2412,       0, 0, 0, SUC, 1, 0 },
	{ "ap_index_int_min_iface_matches", INT_MIN, 1, 1, 10, 1, 2412,       0, 0, 0, SUC, 1, 0 },
	{ "mlme_rc_minus_1",                   0, 1, 1,    10, 1, 2412,       0, -1, 0, ERR, 1, 0 },
	{ "mlme_rc_1",                         0, 1, 1,    10, 1, 2412,       0, 1, 0, ERR, 1, 0 },
	{ "mlme_rc_5",                         0, 1, 1,    10, 1, 2412,       0, 5, 0, ERR, 1, 0 },
	{ "mlme_rc_int_min",                   0, 1, 1,    10, 1, 2412,       0, INT_MIN, 0, ERR, 1, 0 },
	{ "iface_missing",                     0, 0, 1,    10, 1, 2412,       0, 0, 0, ERR, 0, 0 },
	{ "iface_other_vap_index",             0, 2, 1,    10, 1, 2412,       0, 0, 0, ERR, 0, 0 },
	{ "ap_index_negative_iface_other",    -1, 2, 1,    10, 1, 2412,       0, 0, 0, ERR, 0, 0 },
	{ "ap_index_int_min_iface_missing", INT_MIN, 0, 1, 10, 1, 2412,       0, 0, 0, ERR, 0, 0 },
	{ "iface_missing_len_0",               0, 0, 1,     0, 1, 2412,       0, 0, 0, ERR, 0, 0 },
	{ "iface_missing_len_65535",           0, 0, 1, 65535, 1, 2412,       0, 0, 0, ERR, 0, 0 },
	{ "iface_missing_mac_null",            0, 0, 1,    10, 0, 2412,       0, 0, 0, ERR, 0, 0 },
	{ "alloc_fails_len_10",                0, 1, 1,    10, 1, 2412,       0, 0, 1, ERR, 0, 0 },
	{ "alloc_fails_len_65535",             0, 1, 1, 65535, 1, 2412,       0, 0, 1, ERR, 0, 0 },
	{ "alloc_fails_iface_missing",         0, 0, 1,    10, 1, 2412,       0, 0, 1, ERR, 0, 0 },
	/* ---- crash rows (run last) ---- */
	{ "crash_frame_null_len_1",            0, 1, 0,     1, 1, 2412,       0, 0, 0, ERR, 0, 1 },
	{ "crash_frame_null_len_100",          0, 1, 0,   100, 1, 2412,       0, 0, 0, ERR, 0, 1 },
	{ "crash_frame_null_len_4096",         0, 1, 0,  4096, 1, 2412,       0, 0, 0, ERR, 0, 1 },
	{ "crash_frame_null_iface_missing",    0, 0, 0,    10, 1, 2412,       0, 0, 0, ERR, 0, 1 },
	{ "crash_mac_null_iface_ok",           0, 1, 1,    10, 0, 2412,       0, 0, 0, ERR, 0, 1 },
	{ "crash_mac_null_frame_null",         0, 1, 0,    10, 0, 2412,       0, 0, 0, ERR, 0, 1 },
	{ "crash_len_0_frame_ok",              0, 1, 1,     0, 1, 2412,       0, 0, 0, ERR, 0, 1 },
	{ "crash_len_0_frame_null",            0, 1, 0,     0, 1, 2412,       0, 0, 0, ERR, 0, 1 },
	{ NULL }
};
