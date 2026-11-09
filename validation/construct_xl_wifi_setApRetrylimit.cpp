/*
 * UNIT TEST (input constructor): construct_xl_wifi_setApRetrylimit
 *
 * wifi_setApRetrylimit(priv) (platform/xle) is an empty stub that returns 0; priv is not used and nothing is logged.  Inputs crossed: priv NULL / a
 * pointer to a fully POISONED runner slab (the function must not read or write it) / a dangling pointer (0xdeadbeef), repeated calls, and a log slot
 * that is empty / holds text / is almost full / is full (it must stay exactly as it was).  Mode: 0 NULL, 1 poisoned slab, 2 dangling.
 */
#include "hwr_xrl.h"

#define OK 0

/* name, in_mode, calls, prefill, expected_ret */
hwr_xrl_case_t xl_wifi_setApRetrylimit_suite[] = {
	{ "in_null",                    0,  1,   0, OK },
	{ "in_poisoned_slab",           1,  1,   0, OK },
	{ "in_dangling",                2,  1,   0, OK },
	{ "in_null_two_calls",          0,  2,   0, OK },
	{ "in_poisoned_two_calls",      1,  2,   0, OK },
	{ "in_dangling_two_calls",      2,  2,   0, OK },
	{ "in_null_ten_calls",          0, 10,   0, OK },
	{ "in_poisoned_ten_calls",      1, 10,   0, OK },
	{ "log_prefilled_1",              1,  1,   1, OK },
	{ "log_prefilled_100",            1,  1, 100, OK },
	{ "log_almost_full",              1,  1, 254, OK },
	{ "log_full",                     1,  1, 255, OK },
	{ "log_full_in_null",           0,  1, 255, OK },
	{ "log_full_in_dangling",       2,  1, 255, OK },
	{ NULL, 0, 0, 0, 0 }
};
