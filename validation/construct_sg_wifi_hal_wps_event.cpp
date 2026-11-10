/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_wps_event
 *
 * wifi_hal_wps_event(data) with data = { vap_index, event, wps_data } passed by value.  Inputs crossed: platform hook absent / present; hook result 0, 1, -1, -4, INT_MAX, INT_MIN
 * (returned unchanged); vap_index 0, 1, 15, UINT_MAX; event 0, 1, 5, UINT_MAX; wps_data NULL / pointer to a fully POISONED runner slab (never read or written by the wrapper) /
 * dangling; repeated calls; a log slot that is empty / holds text / is almost full / is full.  Expected: no hook -> -1 and no hook call; hook present -> its result, called once
 * per call with the structure UNCHANGED.
 */
#include "hwr_wwe.h"
#include <limits.h>

#define OK 0
#define ER -1
#define U UINT_MAX
/* name, hook_present, hook_ret, vap_index, event, data_mode, calls, prefill, expected_ret */
hwr_wwe_case_t sg_wifi_hal_wps_event_suite[] = {
	{ "hook_ok_slab",                  1, 0,       0, 0, 1,  1,   0, OK },
	{ "hook_ok_vap1_event1",           1, 0,       1, 1, 1,  1,   0, OK },
	{ "hook_ok_vap15_event5",          1, 0,      15, 5, 1,  1,   0, OK },
	{ "hook_ok_vap_uint_max",          1, 0,       U, 0, 1,  1,   0, OK },
	{ "hook_ok_event_uint_max",        1, 0,       0, U, 1,  1,   0, OK },
	{ "hook_ok_all_uint_max",          1, 0,       U, U, 1,  1,   0, OK },
	{ "hook_ok_data_null",             1, 0,       1, 1, 0,  1,   0, OK },
	{ "hook_ok_data_dangling",         1, 0,       1, 1, 2,  1,   0, OK },
	{ "hook_fails",                    1, -1,      1, 1, 1,  1,   0, ER },
	{ "hook_returns_1",                1, 1,       1, 1, 1,  1,   0, 1 },
	{ "hook_returns_minus_4",          1, -4,      1, 1, 1,  1,   0, -4 },
	{ "hook_returns_int_max",          1, INT_MAX, 1, 1, 1,  1,   0, INT_MAX },
	{ "hook_returns_int_min",          1, INT_MIN, 1, 1, 1,  1,   0, INT_MIN },
	{ "hook_ok_two_calls",             1, 0,       2, 3, 1,  2,   0, OK },
	{ "hook_ok_fifty_calls",           1, 0,       2, 3, 1, 50,   0, OK },
	{ "no_hook_slab",                  0, 0,       1, 1, 1,  1,   0, ER },
	{ "no_hook_data_null",             0, 0,       1, 1, 0,  1,   0, ER },
	{ "no_hook_data_dangling",         0, 0,       1, 1, 2,  1,   0, ER },
	{ "no_hook_all_uint_max",          0, 0,       U, U, 1,  1,   0, ER },
	{ "no_hook_hook_ret_ignored",      0, 7,       1, 1, 1,  1,   0, ER },
	{ "no_hook_two_calls",             0, 0,       1, 1, 1,  2,   0, ER },
	{ "no_hook_fifty_calls",           0, 0,       1, 1, 1, 50,   0, ER },
	{ "hook_ok_log_prefilled",         1, 0,       1, 1, 1,  1, 100, OK },
	{ "hook_ok_log_almost_full",       1, 0,       1, 1, 1,  1, 254, OK },
	{ "hook_ok_log_full",              1, 0,       1, 1, 1,  1, 255, OK },
	{ "no_hook_log_full",              0, 0,       1, 1, 1,  1, 255, ER },
	{ NULL, 0, 0, 0, 0, 0, 0, 0, 0 }
};
