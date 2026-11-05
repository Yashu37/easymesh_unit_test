/*
 * UNIT TEST (input constructor): construct_nvram_get_radio_enable_status
 *
 * nvram_get_radio_enable_status(radio_enable, radio_index) (platform/banana-pi) is the platform's "read the radio enable flag
 * from nvram" hook.  The banana-pi version logs and returns 0 without writing *radio_enable, so the caller treats an
 * uninitialised bool as the nvram value.  The runner owns the bool in a slab (preset 0xA5, tail from byte 1 POISONED) and the
 * log slot; it calls the function and checks the contract this harness expects of a platform without nvram: -1 ("not
 * available") and *radio_enable untouched.  Inputs crossed: radio_index 0 / 1 / 2 / 3 / -1 / INT_MAX / INT_MIN, radio_enable
 * NULL, repeated calls, a prefilled / almost full / full log.  The unfixed function returns 0 in every row (finding).
 */
#include <limits.h>
#include "hwr_nre.h"

/* name, radio_index, out_null, calls, prefill, expected_ret */
hwr_nre_case_t nvram_get_radio_enable_status_suite[] = {
	{ "radio_0",                     0,       0, 1,   0, -1 },
	{ "radio_1",                     1,       0, 1,   0, -1 },
	{ "radio_2",                     2,       0, 1,   0, -1 },
	{ "radio_3",                     3,       0, 1,   0, -1 },
	{ "radio_minus_1",              -1,       0, 1,   0, -1 },
	{ "radio_int_max",               INT_MAX, 0, 1,   0, -1 },
	{ "radio_int_min",               INT_MIN, 0, 1,   0, -1 },
	{ "out_null",                    0,       1, 1,   0, -1 },
	{ "out_null_radio_max",          INT_MAX, 1, 1,   0, -1 },
	{ "two_calls",                   1,       0, 2,   0, -1 },
	{ "log_prefilled_100",           0,       0, 1, 100, -1 },
	{ "log_almost_full",             0,       0, 1, 254, -1 },
	{ "log_full_nothing_written",    0,       0, 1, 255, -1 },
	{ NULL, 0, 0, 0, 0, 0 }
};
