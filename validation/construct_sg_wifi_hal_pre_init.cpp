/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_pre_init
 *
 * wifi_hal_pre_init(): asks for the platform pre-init hook once, runs it when it exists, logs, returns 0 always.  Inputs crossed: hook present / absent, repeated calls
 * (1, 2, 5, 50), a log slot that is empty / holds text / is almost full / is full.  Expected: 0; one getter call per call; one hook call per call only when the hook exists.
 */
#include "hwr_wpi.h"

#define OK 0
/* name, hook_present, calls, prefill, expected_ret */
hwr_wpi_case_t sg_wifi_hal_pre_init_suite[] = {
	{ "hook_present",                1,  1,   0, OK },
	{ "hook_absent",                 0,  1,   0, OK },
	{ "hook_present_two_calls",      1,  2,   0, OK },
	{ "hook_absent_two_calls",       0,  2,   0, OK },
	{ "hook_present_five_calls",     1,  5,   0, OK },
	{ "hook_absent_five_calls",      0,  5,   0, OK },
	{ "hook_present_fifty_calls",    1, 50,   0, OK },
	{ "hook_absent_fifty_calls",     0, 50,   0, OK },
	{ "hook_present_log_prefilled",  1,  1, 100, OK },
	{ "hook_absent_log_prefilled",   0,  1, 100, OK },
	{ "hook_present_log_almost_full",1,  1, 254, OK },
	{ "hook_present_log_full",       1,  1, 255, OK },
	{ "hook_absent_log_full",        0,  1, 255, OK },
	{ "hook_present_log_full_3calls",1,  3, 255, OK },
	{ NULL, 0, 0, 0, 0 }
};
