/*
 * UNIT TEST (input constructor): construct_rp_wifi_getRadioChannel
 *
 * wifi_getRadioChannel(radioIndex, output_ulong) (platform/raspberry-pi) is an empty stub that returns 0 for every input: *output_ulong is not written and
 * nothing is logged.  The suite pins that contract.  Inputs crossed: radioIndex 0 / 1 / 2 / 15 / -1 / INT_MIN / INT_MAX, output_ulong NULL / a fully POISONED
 * 8-byte slot inside a canary slab holding a stale value / a dangling pointer, repeated calls, and a log slot that is empty / holds text / is almost full /
 * is full.  Checks: return value 0, the output slot still the stale value and its canary bytes unchanged, the guard slab, the whole log unchanged.
 * Row: name, radio_index, out_mode, calls, prefill, expected_ret.
 */
#include <limits.h>
#include "hwr_rgc.h"

#define OK 0

hwr_rgc_case_t rp_wifi_getRadioChannel_suite[] = {
	{ "radio_0",                     0, 1,  1,   0, OK },
	{ "radio_1",                     1, 1,  1,   0, OK },
	{ "radio_2",                     2, 1,  1,   0, OK },
	{ "radio_15",                   15, 1,  1,   0, OK },
	{ "radio_negative",             -1, 1,  1,   0, OK },
	{ "radio_int_min",         INT_MIN, 1,  1,   0, OK },
	{ "radio_int_max",         INT_MAX, 1,  1,   0, OK },
	{ "out_null",                    0, 0,  1,   0, OK },
	{ "out_null_radio_1",            1, 0,  1,   0, OK },
	{ "out_null_radio_int_min",INT_MIN, 0,  1,   0, OK },
	{ "out_dangling",                0, 2,  1,   0, OK },
	{ "out_dangling_radio_1",        1, 2,  1,   0, OK },
	{ "two_calls_slab",              0, 1,  2,   0, OK },
	{ "ten_calls_slab",              1, 1, 10,   0, OK },
	{ "ten_calls_null",              1, 0, 10,   0, OK },
	{ "two_calls_dangling",          0, 2,  2,   0, OK },
	{ "log_prefilled_1",             0, 1,  1,   1, OK },
	{ "log_prefilled_100",           0, 1,  1, 100, OK },
	{ "log_almost_full",             0, 1,  1, 254, OK },
	{ "log_full",                    0, 1,  1, 255, OK },
	{ "log_full_out_null",           0, 0,  1, 255, OK },
	{ "log_full_out_dangling",       0, 2,  1, 255, OK },
	{ NULL, 0, 0, 0, 0, 0 }
};
