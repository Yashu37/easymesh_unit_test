/*
 * UNIT TEST (input constructor): construct_int_wifi_pushApRoamingConsortiumElement
 *
 * wifi_pushApRoamingConsortiumElement(apIndex, infoElement) (platform/intel) is an empty stub that returns RETURN_ERR (-1) for every input and never touches
 * infoElement (the struct is read-only input here: nothing is parsed or stored): the platform reports pushing the Roaming Consortium element as unsupported.  The suite pins that contract: every combination returns WIFI_HAL_ERROR,
 * leaves the output structure (stale 0x5A bytes inside a canary slab that is entirely POISONED during the call, so any read or write aborts), the guard
 * slab and the log untouched.  Inputs crossed: apIndex 0 / 1 / 2 / 15 / -1 / INT_MIN / INT_MAX, output NULL / the runner's structure / dangling,
 * repeated calls, and a log slot that is empty / holds text / is almost full / is full.
 */
#include <limits.h>
#include "hwr_ipr.h"

#define ERR WIFI_HAL_ERROR

/* name, ap_index, out_mode (0 NULL, 1 poisoned structure, 2 dangling), calls, prefill, expected_ret */
hwr_ipr_case_t int_wifi_pushApRoamingConsortiumElement_suite[] = {
	{ "ap_0_valid_output",          0,       1,  1,   0, ERR },
	{ "ap_1_valid_output",          1,       1,  1,   0, ERR },
	{ "ap_2_valid_output",          2,       1,  1,   0, ERR },
	{ "ap_15_valid_output",        15,       1,  1,   0, ERR },
	{ "ap_negative_valid_output",  -1,       1,  1,   0, ERR },
	{ "ap_int_min_valid_output", INT_MIN,    1,  1,   0, ERR },
	{ "ap_int_max_valid_output", INT_MAX,    1,  1,   0, ERR },
	{ "ap_0_output_null",           0,       0,  1,   0, ERR },
	{ "ap_1_output_null",           1,       0,  1,   0, ERR },
	{ "ap_15_output_null",         15,       0,  1,   0, ERR },
	{ "ap_negative_output_null",   -1,       0,  1,   0, ERR },
	{ "ap_int_min_output_null", INT_MIN,     0,  1,   0, ERR },
	{ "ap_int_max_output_null", INT_MAX,     0,  1,   0, ERR },
	{ "ap_0_output_dangling",       0,       2,  1,   0, ERR },
	{ "ap_15_output_dangling",     15,       2,  1,   0, ERR },
	{ "two_calls_valid_output",     0,       1,  2,   0, ERR },
	{ "ten_calls_valid_output",     3,       1, 10,   0, ERR },
	{ "two_calls_output_null",      0,       0,  2,   0, ERR },
	{ "ten_calls_output_dangling",  1,       2, 10,   0, ERR },
	{ "log_prefilled_1",            0,       1,  1,   1, ERR },
	{ "log_prefilled_100",          0,       1,  1, 100, ERR },
	{ "log_almost_full",            0,       1,  1, 254, ERR },
	{ "log_full",                   0,       1,  1, 255, ERR },
	{ "log_full_output_null",       0,       0,  1, 255, ERR },
	{ NULL, 0, 0, 0, 0, 0 }
};
