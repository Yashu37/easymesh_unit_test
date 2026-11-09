/*
 * UNIT TEST (input constructor): construct_em_wifi_rrm_send_beacon_req
 *
 * wifi_rrm_send_beacon_req(...) (platform/wifi-emulator) is an empty stub returning 0 for every input: none of the 22 arguments is read and nothing is logged.
 * The suite pins that contract.  Inputs crossed: all pointer arguments (interface, addr, bssid, ssid, rep_cond, rep_cond_threshold, rep_detail, ap_ch_rep, req_elem,
 * ch_width, ch_center_freq0, ch_center_freq1) NULL / pointing into a fully POISONED slab / dangling; the 16-bit and length arguments 0 / 1 / 100 / 0xFFFF /
 * UINT_MAX; every u8 argument 0 / 1 / 0x7F / 0x80 / 0xFF; repeated calls; and a log slot that is empty / holds text / is almost full / is full.  Checks: return
 * value 0, the slab, the guard slab and the whole log unchanged.  Row: name, ptr_mode, reps, small, calls, prefill, expected_ret.
 */
#include <limits.h>
#include "hwr_esb.h"

#define OK 0

hwr_esb_case_t em_wifi_rrm_send_beacon_req_suite[] = {
	{ "ptrs_null_zero_values",             0,          0,    0,  1,   0, OK },
	{ "ptrs_slab_zero_values",             1,          0,    0,  1,   0, OK },
	{ "ptrs_dangling_zero_values",         2,          0,    0,  1,   0, OK },
	{ "ptrs_null_typical_values",          0,        100,    1,  1,   0, OK },
	{ "ptrs_slab_typical_values",          1,        100,    1,  1,   0, OK },
	{ "ptrs_dangling_typical_values",      2,        100,    1,  1,   0, OK },
	{ "ptrs_null_reps_1",                  0,          1,    1,  1,   0, OK },
	{ "ptrs_slab_reps_1",                  1,          1,    1,  1,   0, OK },
	{ "ptrs_null_reps_0xffff",             0,     0xFFFF,    1,  1,   0, OK },
	{ "ptrs_slab_reps_0xffff",             1,     0xFFFF,    1,  1,   0, OK },
	{ "ptrs_null_reps_uint_max",           0,   UINT_MAX,    1,  1,   0, OK },
	{ "ptrs_slab_reps_uint_max",           1,   UINT_MAX,    1,  1,   0, OK },
	{ "ptrs_dangling_reps_uint_max",       2,   UINT_MAX,    1,  1,   0, OK },
	{ "ptrs_null_u8_0x7f",                 0,        100,  0x7F, 1,   0, OK },
	{ "ptrs_slab_u8_0x7f",                 1,        100,  0x7F, 1,   0, OK },
	{ "ptrs_null_u8_0x80",                 0,        100,  0x80, 1,   0, OK },
	{ "ptrs_slab_u8_0x80",                 1,        100,  0x80, 1,   0, OK },
	{ "ptrs_null_u8_0xff",                 0,        100,  0xFF, 1,   0, OK },
	{ "ptrs_slab_u8_0xff",                 1,        100,  0xFF, 1,   0, OK },
	{ "ptrs_dangling_u8_0xff",             2,        100,  0xFF, 1,   0, OK },
	{ "all_extremes_slab",                 1,   UINT_MAX,  0xFF, 1,   0, OK },
	{ "all_extremes_dangling",             2,   UINT_MAX,  0xFF, 1,   0, OK },
	{ "two_calls_slab",                    1,        100,    1,  2,   0, OK },
	{ "ten_calls_null",                    0,        100,    1, 10,   0, OK },
	{ "ten_calls_slab",                    1,        100,    1, 10,   0, OK },
	{ "log_prefilled_1",                   1,        100,    1,  1,   1, OK },
	{ "log_prefilled_100",                 1,        100,    1,  1, 100, OK },
	{ "log_almost_full",                   1,        100,    1,  1, 254, OK },
	{ "log_full",                          1,        100,    1,  1, 255, OK },
	{ "log_full_ptrs_null",                0,        100,    1,  1, 255, OK },
	{ NULL, 0, 0, 0, 0, 0, 0 }
};
