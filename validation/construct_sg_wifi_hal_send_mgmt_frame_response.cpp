/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_send_mgmt_frame_response
 *
 * wifi_hal_send_mgmt_frame_response(ap_index, type, status, status_code, frame, mac, len, rssi).  Inputs crossed: status 0 (OK) / 1 (DENY) / 2, -1, 7, INT_MAX, INT_MIN (undefined);
 * ap_index 0, 1, 15, -1, INT_MAX; type 0, 0x10 (assoc resp), 0x30 (reassoc resp), -1; status_code 0, 1, 17, -1; frame and mac NULL / pointers into fully POISONED runner slabs (never
 * read or written by the wrapper) / dangling; len 0, 1, 24, 2000, -1, INT_MAX; rssi 0, -90, 100, INT_MIN; repeated calls; a log slot that is empty / holds text / is almost full / is
 * full.  Expected: OK -> the supplicant-event callee once with (ap_index, frame, len) and 0; DENY -> the failure callee once with (ap_index, mac, type, status_code, rssi) and 0;
 * any other status -> -1, no callee, the "Undefined status" log.
 */
#include "hwr_wmr.h"
#include <limits.h>

#define OK 0
#define ER -1
/* name, status, ap_index, type, status_code, ptr_mode, len, rssi, calls, prefill, expected_ret */
hwr_wmr_case_t sg_wifi_hal_send_mgmt_frame_response_suite[] = {
	{ "ok_slabs",                    0,  1, 0x10,  0, 1,   24,  -40,  1,   0, OK },
	{ "ok_ap0",                      0,  0, 0x10,  0, 1,   24,  -40,  1,   0, OK },
	{ "ok_ap15",                     0, 15, 0x10,  0, 1,   24,  -40,  1,   0, OK },
	{ "ok_ap_minus1",                0, -1, 0x10,  0, 1,   24,  -40,  1,   0, OK },
	{ "ok_ap_int_max",               0, INT_MAX, 0x10, 0, 1, 24, -40, 1,   0, OK },
	{ "ok_len0",                     0,  1, 0x10,  0, 1,    0,  -40,  1,   0, OK },
	{ "ok_len1",                     0,  1, 0x10,  0, 1,    1,  -40,  1,   0, OK },
	{ "ok_len2000_not_backed",       0,  1, 0x10,  0, 1, 2000,  -40,  1,   0, OK },
	{ "ok_len_minus1",               0,  1, 0x10,  0, 1,   -1,  -40,  1,   0, OK },
	{ "ok_len_int_max",              0,  1, 0x10,  0, 1, INT_MAX, -40, 1,  0, OK },
	{ "ok_frame_null",               0,  1, 0x10,  0, 0,   24,  -40,  1,   0, OK },
	{ "ok_frame_dangling",           0,  1, 0x10,  0, 2,   24,  -40,  1,   0, OK },
	{ "ok_two_calls",                0,  2, 0x30,  0, 1,   24,  -40,  2,   0, OK },
	{ "ok_fifty_calls",              0,  2, 0x30,  0, 1,   24,  -40, 50,   0, OK },
	{ "deny_slabs",                  1,  1, 0x10, 17, 1,   24,  -40,  1,   0, OK },
	{ "deny_reassoc",                1,  1, 0x30, 17, 1,   24,  -40,  1,   0, OK },
	{ "deny_type0",                  1,  1,    0,  0, 1,   24,  -40,  1,   0, OK },
	{ "deny_type_minus1",            1,  1,   -1,  0, 1,   24,  -40,  1,   0, OK },
	{ "deny_status_code_minus1",     1,  1, 0x10, -1, 1,   24,  -40,  1,   0, OK },
	{ "deny_rssi_0",                 1,  1, 0x10, 17, 1,   24,    0,  1,   0, OK },
	{ "deny_rssi_100",               1,  1, 0x10, 17, 1,   24,  100,  1,   0, OK },
	{ "deny_rssi_int_min",           1,  1, 0x10, 17, 1,   24, INT_MIN, 1, 0, OK },
	{ "deny_ap_minus1",              1, -1, 0x10, 17, 1,   24,  -40,  1,   0, OK },
	{ "deny_mac_null",               1,  1, 0x10, 17, 0,   24,  -40,  1,   0, OK },
	{ "deny_mac_dangling",           1,  1, 0x10, 17, 2,   24,  -40,  1,   0, OK },
	{ "deny_two_calls",              1,  2, 0x10, 17, 1,   24,  -40,  2,   0, OK },
	{ "deny_fifty_calls",            1,  2, 0x10, 17, 1,   24,  -40, 50,   0, OK },
	{ "undefined_status_2",          2,  1, 0x10,  0, 1,   24,  -40,  1,   0, ER },
	{ "undefined_status_minus1",    -1,  1, 0x10,  0, 1,   24,  -40,  1,   0, ER },
	{ "undefined_status_7",          7,  1, 0x10,  0, 1,   24,  -40,  1,   0, ER },
	{ "undefined_status_int_max",   INT_MAX, 1, 0x10, 0, 1, 24, -40,  1,   0, ER },
	{ "undefined_status_int_min",   INT_MIN, 1, 0x10, 0, 1, 24, -40,  1,   0, ER },
	{ "undefined_ptrs_null",         2,  1, 0x10,  0, 0,   24,  -40,  1,   0, ER },
	{ "undefined_ptrs_dangling",     2,  1, 0x10,  0, 2,   24,  -40,  1,   0, ER },
	{ "undefined_two_calls",         2,  1, 0x10,  0, 1,   24,  -40,  2,   0, ER },
	{ "ok_log_prefilled",            0,  1, 0x10,  0, 1,   24,  -40,  1, 100, OK },
	{ "ok_log_full",                 0,  1, 0x10,  0, 1,   24,  -40,  1, 255, OK },
	{ "deny_log_full",               1,  1, 0x10, 17, 1,   24,  -40,  1, 255, OK },
	{ "undefined_log_full",          2,  1, 0x10,  0, 1,   24,  -40,  1, 255, ER },
	{ NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};
