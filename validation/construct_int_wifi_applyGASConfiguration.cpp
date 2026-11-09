/*
 * UNIT TEST (input constructor): construct_int_wifi_applyGASConfiguration
 *
 * wifi_applyGASConfiguration(input_struct) (platform/intel) is an empty stub that returns RETURN_ERR (-1); input_struct is not used and nothing is logged.  Inputs crossed: input_struct NULL / a
 * pointer to a fully POISONED runner slab (the function must not read or write it) / a dangling pointer (0xdeadbeef), repeated calls, and a log slot
 * that is empty / holds text / is almost full / is full (it must stay exactly as it was).  Mode: 0 NULL, 1 poisoned slab, 2 dangling.
 */
#include "hwr_iga.h"

#define ERR RETURN_ERR

/* name, in_mode, calls, prefill, expected_ret */
hwr_iga_case_t int_wifi_applyGASConfiguration_suite[] = {
	{ "in_null",                    0,  1,   0, ERR },
	{ "in_poisoned_slab",           1,  1,   0, ERR },
	{ "in_dangling",                2,  1,   0, ERR },
	{ "in_null_two_calls",          0,  2,   0, ERR },
	{ "in_poisoned_two_calls",      1,  2,   0, ERR },
	{ "in_dangling_two_calls",      2,  2,   0, ERR },
	{ "in_null_ten_calls",          0, 10,   0, ERR },
	{ "in_poisoned_ten_calls",      1, 10,   0, ERR },
	{ "log_prefilled_1",              1,  1,   1, ERR },
	{ "log_prefilled_100",            1,  1, 100, ERR },
	{ "log_almost_full",              1,  1, 254, ERR },
	{ "log_full",                     1,  1, 255, ERR },
	{ "log_full_in_null",           0,  1, 255, ERR },
	{ "log_full_in_dangling",       2,  1, 255, ERR },
	{ NULL, 0, 0, 0, 0 }
};
