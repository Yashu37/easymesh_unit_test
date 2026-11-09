/*
 * UNIT TEST (input constructor): construct_rp_wifi_steering_clientDisconnect
 *
 * wifi_steering_clientDisconnect(steeringgroupIndex, apIndex, client_mac, type, reason) (platform/raspberry-pi) is an empty stub that returns 0 for every input:
 * client_mac is not read and nothing is logged.  The suite pins that contract.  Inputs crossed: steeringgroupIndex 0 / 1 / 255 / UINT_MAX, apIndex 0 / 1 / 15 / -1 /
 * INT_MIN / INT_MAX, type 0 / 1 / 2 / -1 / INT_MAX (any value of the enum), reason 0 / 1 / 3 / 255 / UINT_MAX, the 6-byte client_mac array fully POISONED, repeated
 * calls, and a log slot that is empty / holds text / is almost full / is full.  Checks: return value 0, the MAC bytes, the guard slab and the whole log unchanged.
 * Row: name, group_index, ap_index, type, reason, calls, prefill, expected_ret.
 */
#include <limits.h>
#include "hwr_rcd.h"

#define OK 0

hwr_rcd_case_t rp_wifi_steering_clientDisconnect_suite[] = {
	{ "typical_group0_ap0_type1",           0,       0,       1,        1,  1,   0, OK },
	{ "type_0",                             0,       0,       0,        1,  1,   0, OK },
	{ "type_2",                             0,       0,       2,        1,  1,   0, OK },
	{ "type_negative",                      0,       0,      -1,        1,  1,   0, OK },
	{ "type_int_max",                       0,       0, INT_MAX,        1,  1,   0, OK },
	{ "reason_0",                           0,       0,       1,        0,  1,   0, OK },
	{ "reason_3",                           0,       0,       1,        3,  1,   0, OK },
	{ "reason_255",                         0,       0,       1,      255,  1,   0, OK },
	{ "reason_uint_max",                    0,       0,       1, UINT_MAX,  1,   0, OK },
	{ "group_1",                            1,       0,       1,        1,  1,   0, OK },
	{ "group_255",                        255,       0,       1,        1,  1,   0, OK },
	{ "group_uint_max",              UINT_MAX,       0,       1,        1,  1,   0, OK },
	{ "ap_1",                               0,       1,       1,        1,  1,   0, OK },
	{ "ap_15",                              0,      15,       1,        1,  1,   0, OK },
	{ "ap_negative",                        0,      -1,       1,        1,  1,   0, OK },
	{ "ap_int_min",                         0, INT_MIN,       1,        1,  1,   0, OK },
	{ "ap_int_max",                         0, INT_MAX,       1,        1,  1,   0, OK },
	{ "all_extremes",                UINT_MAX, INT_MIN, INT_MAX, UINT_MAX,  1,   0, OK },
	{ "two_calls",                          0,       0,       1,        1,  2,   0, OK },
	{ "ten_calls",                          1,       2,       2,        3, 10,   0, OK },
	{ "log_prefilled_1",                    0,       0,       1,        1,  1,   1, OK },
	{ "log_prefilled_100",                  0,       0,       1,        1,  1, 100, OK },
	{ "log_almost_full",                    0,       0,       1,        1,  1, 254, OK },
	{ "log_full",                           0,       0,       1,        1,  1, 255, OK },
	{ NULL, 0, 0, 0, 0, 0, 0, 0 }
};
