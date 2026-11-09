/*
 * UNIT TEST (input constructor): construct_wifi_getRadioChannelStats
 *
 * wifi_getRadioChannelStats(radioIndex, array, array_size) (platform/banana-pi) is an empty stub that returns RETURN_OK.  The HAL interface
 * (halinterface wifi_hal_extender.h:887) says the array is pre-filled with the channel numbers to query and the function fills the statistics of
 * those channels (array_size 0: one ONCHAN element), returning WIFI_HAL_SUCCESS, or WIFI_HAL_ERROR on any error.  The stub fills nothing, so a
 * caller that trusts the success reads stale / uninitialised statistics.  The suite expects what a platform without channel statistics must do:
 * report WIFI_HAL_ERROR and leave the array alone.  Inputs crossed: radioIndex 0 / 1 / 2 / -1 / INT_MIN / INT_MAX, array NULL / the runner's
 * 64-entry array, array_size 0 / 1 / 2 / 16 / 64 / 65 / 1000 / -1 / INT_MIN / INT_MAX, repeated calls.
 */
#include <limits.h>
#include "hwr_gks.h"

#define ERR WIFI_HAL_ERROR

/* name, radio_index, array_mode, array_size, calls, expected_ret */
hwr_gks_case_t wifi_getRadioChannelStats_suite[] = {
	{ "radio_0_size_0_onchan",            0, 1,        0, 1, ERR },
	{ "radio_0_size_1",                   0, 1,        1, 1, ERR },
	{ "radio_0_size_2",                   0, 1,        2, 1, ERR },
	{ "radio_0_size_16",                  0, 1,       16, 1, ERR },
	{ "radio_0_size_64_full_array",       0, 1,       64, 1, ERR },
	{ "radio_0_size_65_beyond_array",     0, 1,       65, 1, ERR },
	{ "radio_0_size_1000",                0, 1,     1000, 1, ERR },
	{ "radio_0_size_int_max",             0, 1,  INT_MAX, 1, ERR },
	{ "radio_0_size_minus_1",             0, 1,       -1, 1, ERR },
	{ "radio_0_size_int_min",             0, 1,  INT_MIN, 1, ERR },
	{ "radio_1_size_16",                  1, 1,       16, 1, ERR },
	{ "radio_2_size_16",                  2, 1,       16, 1, ERR },
	{ "radio_negative_size_16",          -1, 1,       16, 1, ERR },
	{ "radio_int_min_size_16",       INT_MIN, 1,       16, 1, ERR },
	{ "radio_int_max_size_16",       INT_MAX, 1,       16, 1, ERR },
	{ "two_calls",                        0, 1,        8, 2, ERR },
	{ "ten_calls",                        0, 1,        8, 10, ERR },
	{ "array_null_size_0",                0, 0,        0, 1, ERR },
	{ "array_null_size_1",                0, 0,        1, 1, ERR },
	{ "array_null_size_16",               0, 0,       16, 1, ERR },
	{ "array_null_size_minus_1",          0, 0,       -1, 1, ERR },
	{ "array_null_size_int_max",          0, 0,  INT_MAX, 1, ERR },
	{ "array_null_radio_negative",       -1, 0,       16, 1, ERR },
	{ "array_null_radio_int_max",    INT_MAX, 0,       16, 1, ERR },
	{ NULL, 0, 0, 0, 0, 0 }
};
