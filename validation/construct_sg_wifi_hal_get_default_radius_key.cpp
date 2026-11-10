/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_get_default_radius_key
 *
 * wifi_hal_get_default_radius_key(radius_key).  Inputs crossed: platform hook absent / present; hook result 0, 1, -1, -4, INT_MAX, INT_MIN (returned unchanged); radius_key NULL /
 * pointer to a fully POISONED runner slab (the wrapper must not read or write it) / dangling; repeated calls; a log slot that is
 * empty / holds text / is almost full / is full.  Expected: no hook -> -1 and no hook call; hook present -> its result, called once per call with the same radius_key pointer.
 */
#include "hwr_wrk.h"
#include <limits.h>

#define OK 0
#define ER -1
/* name, hook_present, hook_ret, key_mode, calls, prefill, expected_ret */
hwr_wrk_case_t sg_wifi_hal_get_default_radius_key_suite[] = {
	{ "hook_ok_slab", 1, 0, 1, 1, 0, OK },
	{ "hook_ok_code_null", 1, 0, 0, 1, 0, OK },
	{ "hook_ok_code_dangling", 1, 0, 2, 1, 0, OK },
	{ "hook_fails", 1, -1, 1, 1, 0, -1 },
	{ "hook_returns_1", 1, 1, 1, 1, 0, 1 },
	{ "hook_returns_minus_4", 1, -4, 1, 1, 0, -4 },
	{ "hook_returns_int_max", 1, INT_MAX, 1, 1, 0, INT_MAX },
	{ "hook_returns_int_min", 1, INT_MIN, 1, 1, 0, INT_MIN },
	{ "hook_ok_two_calls", 1, 0, 1, 2, 0, OK },
	{ "hook_ok_fifty_calls", 1, 0, 1, 50, 0, OK },
	{ "no_hook_slab", 0, 0, 1, 1, 0, ER },
	{ "no_hook_code_null", 0, 0, 0, 1, 0, ER },
	{ "no_hook_code_dangling", 0, 0, 2, 1, 0, ER },
	{ "no_hook_hook_ret_ignored", 0, 7, 1, 1, 0, ER },
	{ "no_hook_two_calls", 0, 0, 1, 2, 0, ER },
	{ "no_hook_fifty_calls", 0, 0, 1, 50, 0, ER },
	{ "hook_ok_log_prefilled", 1, 0, 1, 1, 100, OK },
	{ "hook_ok_log_almost_full", 1, 0, 1, 1, 254, OK },
	{ "hook_ok_log_full", 1, 0, 1, 1, 255, OK },
	{ "no_hook_log_full", 0, 0, 1, 1, 255, ER },
	{ NULL, 0, 0, 0, 0, 0, 0 }
};
