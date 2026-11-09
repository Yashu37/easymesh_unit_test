/*
 * UNIT TEST (input constructor): construct_rp_wifi_getApDeviceRSSI
 *
 * wifi_getApDeviceRSSI(ap_index, MAC, output_RSSI) (platform/raspberry-pi) is an empty stub that returns 0 for every input: MAC is not read, *output_RSSI is not
 * written and nothing is logged.  The suite pins that contract.  Inputs crossed: ap_index 0 / 1 / 15 / -1 / INT_MIN / INT_MAX, MAC NULL / a fully POISONED slab /
 * a dangling pointer, output_RSSI NULL / a POISONED slab slot with a stale value / a dangling pointer, repeated calls, and a log slot that is empty / holds
 * text / is almost full / is full.  Checks: return value 0, the output slot and its canary bytes unchanged, the guard slab, the whole log unchanged.
 * Row: name, ap_index, mac_mode, out_mode, calls, prefill, expected_ret.
 */
#include <limits.h>
#include "hwr_rrs.h"

#define OK 0

hwr_rrs_case_t rp_wifi_getApDeviceRSSI_suite[] = {
	{ "typical_ap0",                 0, 1, 1,  1,   0, OK },
	{ "ap_1",                        1, 1, 1,  1,   0, OK },
	{ "ap_15",                      15, 1, 1,  1,   0, OK },
	{ "ap_negative",                -1, 1, 1,  1,   0, OK },
	{ "ap_int_min",            INT_MIN, 1, 1,  1,   0, OK },
	{ "ap_int_max",            INT_MAX, 1, 1,  1,   0, OK },
	{ "mac_null",                    0, 0, 1,  1,   0, OK },
	{ "mac_dangling",                0, 2, 1,  1,   0, OK },
	{ "out_null",                    0, 1, 0,  1,   0, OK },
	{ "out_dangling",                0, 1, 2,  1,   0, OK },
	{ "mac_null_out_null",           0, 0, 0,  1,   0, OK },
	{ "mac_dangling_out_dangling",   0, 2, 2,  1,   0, OK },
	{ "mac_null_out_slab",           3, 0, 1,  1,   0, OK },
	{ "mac_slab_out_null",           3, 1, 0,  1,   0, OK },
	{ "all_extremes_null",     INT_MIN, 0, 0,  1,   0, OK },
	{ "two_calls",                   0, 1, 1,  2,   0, OK },
	{ "ten_calls_null_pointers",     1, 0, 0, 10,   0, OK },
	{ "ten_calls_slabs",             1, 1, 1, 10,   0, OK },
	{ "log_prefilled_1",             0, 1, 1,  1,   1, OK },
	{ "log_prefilled_100",           0, 1, 1,  1, 100, OK },
	{ "log_almost_full",             0, 1, 1,  1, 254, OK },
	{ "log_full",                    0, 1, 1,  1, 255, OK },
	{ "log_full_null_pointers",      0, 0, 0,  1, 255, OK },
	{ NULL, 0, 0, 0, 0, 0, 0 }
};
