/*
 * UNIT TEST (input constructor): construct_wifi_applyGASConfiguration
 *
 * wifi_applyGASConfiguration(input_struct) (platform/banana-pi) is an empty stub that returns 0; input_struct is not used and nothing is logged.  Inputs crossed: input_struct NULL / a
 * pointer to a fully POISONED runner slab (the function must not read or write it) / a dangling pointer (0xdeadbeef), repeated calls, and a log slot
 * that is empty / holds text / is almost full / is full (it must stay exactly as it was).  Mode: 0 NULL, 1 poisoned slab, 2 dangling.
 */
#include "hwr_aga.h"

/* name, in_mode, calls, prefill, expected_ret */
hwr_aga_case_t wifi_applyGASConfiguration_suite[] = {
	{ "in_null",                    0,  1,   0, 0 },
	{ "in_poisoned_slab",           1,  1,   0, 0 },
	{ "in_dangling",                2,  1,   0, 0 },
	{ "in_null_two_calls",          0,  2,   0, 0 },
	{ "in_poisoned_two_calls",      1,  2,   0, 0 },
	{ "in_dangling_two_calls",      2,  2,   0, 0 },
	{ "in_null_ten_calls",          0, 10,   0, 0 },
	{ "in_poisoned_ten_calls",      1, 10,   0, 0 },
	{ "log_prefilled_1",              1,  1,   1, 0 },
	{ "log_prefilled_100",            1,  1, 100, 0 },
	{ "log_almost_full",              1,  1, 254, 0 },
	{ "log_full",                     1,  1, 255, 0 },
	{ "log_full_in_null",           0,  1, 255, 0 },
	{ "log_full_in_dangling",       2,  1, 255, 0 },
	{ NULL, 0, 0, 0, 0 }
};
