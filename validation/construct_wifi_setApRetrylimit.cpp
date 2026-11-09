/*
 * UNIT TEST (input constructor): construct_wifi_setApRetrylimit
 *
 * wifi_setApRetrylimit(priv) (platform/banana-pi) is an empty stub that returns 0; priv is not used and nothing is logged.  Inputs crossed: priv NULL / a
 * pointer to a fully POISONED runner slab (the function must not read or write it) / a dangling pointer (0xdeadbeef), repeated calls, and a log slot
 * that is empty / holds text / is almost full / is full (it must stay exactly as it was).  Mode: 0 NULL, 1 poisoned slab, 2 dangling.
 */
#include "hwr_srl.h"

/* name, priv_mode, calls, prefill, expected_ret */
hwr_srl_case_t wifi_setApRetrylimit_suite[] = {
	{ "priv_null",                    0,  1,   0, 0 },
	{ "priv_poisoned_slab",           1,  1,   0, 0 },
	{ "priv_dangling",                2,  1,   0, 0 },
	{ "priv_null_two_calls",          0,  2,   0, 0 },
	{ "priv_poisoned_two_calls",      1,  2,   0, 0 },
	{ "priv_dangling_two_calls",      2,  2,   0, 0 },
	{ "priv_null_ten_calls",          0, 10,   0, 0 },
	{ "priv_poisoned_ten_calls",      1, 10,   0, 0 },
	{ "log_prefilled_1",              1,  1,   1, 0 },
	{ "log_prefilled_100",            1,  1, 100, 0 },
	{ "log_almost_full",              1,  1, 254, 0 },
	{ "log_full",                     1,  1, 255, 0 },
	{ "log_full_priv_null",           0,  1, 255, 0 },
	{ "log_full_priv_dangling",       2,  1, 255, 0 },
	{ NULL, 0, 0, 0, 0 }
};
