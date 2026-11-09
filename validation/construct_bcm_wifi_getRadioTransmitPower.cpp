/*
 * UNIT TEST (input constructor): construct_bcm_wifi_getRadioTransmitPower
 *
 * wifi_getRadioTransmitPower (platform/broadcom) forwards (radioIndex, tx_power) to wifi_hal_getRadioTransmitPower and returns its result unchanged.  It
 * never reads or writes the output slot itself and logs nothing.  The suite crosses: core result 0 / RETURN_ERR / other negative and positive values /
 * INT_MIN / INT_MAX, radioIndex 0 / 1 / 2 / -1 / INT_MIN / INT_MAX, the output pointer NULL / the runner's slot (POISONED during the call) / dangling /
 * a slot the core writes 37 into, and repeated calls.  Checks: the core was called once per call with the same arguments, the return value equals the
 * core result, the poisoned slot and the guard slab are untouched, nothing is logged, and a value written by the core arrives unchanged.  The core logic
 * itself belongs to the src module tests.
 */
#include <limits.h>
#include "hwr_bgp.h"

#define OK    0
#define ERR   (-1)

/* name, radioIndex, tx_mode, core_ret, calls */
hwr_bgp_case_t wifi_getRadioTransmitPower_bcm_suite[] = {
	{ "core_ok",                       0, 1, OK,       1 },
	{ "core_error",                    0, 1, ERR,      1 },
	{ "core_minus_2_forwarded",        0, 1, -2,       1 },
	{ "core_minus_5_forwarded",        0, 1, -5,       1 },
	{ "core_positive_1_forwarded",     0, 1, 1,        1 },
	{ "core_int_min_forwarded",        0, 1, INT_MIN,  1 },
	{ "core_int_max_forwarded",        0, 1, INT_MAX,  1 },
	{ "radio_1_ok",                    1, 1, OK,       1 },
	{ "radio_2_error",                 2, 1, ERR,      1 },
	{ "radio_3_ok",                    3, 1, OK,       1 },
	{ "radio_negative_ok",            -1, 1, OK,       1 },
	{ "radio_negative_error",         -1, 1, ERR,      1 },
	{ "radio_int_min_error",     INT_MIN, 1, ERR,      1 },
	{ "radio_int_max_ok",        INT_MAX, 1, OK,       1 },
	{ "tx_null_ok",                    0, 0, OK,       1 },
	{ "tx_null_error",                 0, 0, ERR,      1 },
	{ "tx_dangling_ok",                0, 2, OK,       1 },
	{ "tx_dangling_error",             0, 2, ERR,      1 },
	{ "core_writes_value_ok",          0, 3, OK,       1 },
	{ "core_writes_value_error",       0, 3, ERR,      1 },
	{ "radio_1_core_writes_value",     1, 3, OK,       1 },
	{ "two_calls_ok",                  0, 1, OK,       2 },
	{ "two_calls_error",               0, 1, ERR,      2 },
	{ "ten_calls_ok",                  0, 1, OK,      10 },
	{ "ten_calls_error",               0, 0, ERR,     10 },
	{ NULL, 0, 0, 0, 0 }
};
