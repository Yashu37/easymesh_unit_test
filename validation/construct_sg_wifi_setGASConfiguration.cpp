/*
 * UNIT TEST (input constructor): construct_sg_wifi_setGASConfiguration
 *
 * wifi_setGASConfiguration(advertisementID, input_struct).  Inputs crossed: advertisementID 0 / 1 / 5 / 0x7FFFFFFF / 0xFFFFFFFF; input_struct NULL / an exactly sized heap block holding zeros / ones /
 * distinct values / all 0xFF; one call or two consecutive calls.  Expected (CORRECT behaviour): NULL input or an id other than 0 -> RETURN_ERR, the stored configuration stays unchanged and nothing is
 * applied; id 0 with a valid input -> the stored gasCfg[0] equals the input byte for byte, the platform apply hook runs once with that input, RETURN_OK.  No crash case is expected.
 */
#include "hwr_wgc.h"

/* name, id, input_null, pattern, calls, last */
hwr_wgc_case_t sg_wifi_setGASConfiguration_suite[] = {
	{ "id0_zeros",                  0, 0, 0, 1, 0 },
	{ "id0_ones",                   0, 0, 1, 1, 0 },
	{ "id0_distinct_values",        0, 0, 2, 1, 0 },
	{ "id0_all_ff",                 0, 0, 3, 1, 0 },
	{ "id0_two_calls_overwrite",    0, 0, 2, 2, 0 },
	{ "id0_input_null",             0, 1, 0, 1, 0 },
	{ "id1_valid_input",            1, 0, 2, 1, 0 },
	{ "id5_valid_input",            5, 0, 2, 1, 0 },
	{ "id_int_max",                 0x7FFFFFFF, 0, 2, 1, 0 },
	{ "id_uint_max",                0xFFFFFFFF, 0, 2, 1, 0 },
	{ "id1_input_null",             1, 1, 0, 1, 0 },
	{ "id_uint_max_input_null",     0xFFFFFFFF, 1, 0, 1, 0 },
	{ "valid_then_second_valid",    0, 0, 1, 2, 0 },
	{ NULL }
};
