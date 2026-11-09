/*
 * UNIT TEST (input constructor): construct_wifi_steering_eventRegister
 *
 * wifi_steering_eventRegister(event_cb) (platform/banana-pi) is an empty stub that returns RETURN_OK; the callback is neither stored nor called and
 * nothing is logged.  Inputs crossed: event_cb NULL / the runner's counting callback / a dangling pointer (0xdeadbeef), repeated calls, and a log slot
 * that is empty / holds text / is almost full / is full (it must stay exactly as it was).  The callback must never be invoked.
 * Mode: 0 NULL, 1 counting callback, 2 dangling.
 */
#include "hwr_ser.h"

/* name, cb_mode, calls, prefill, expected_ret */
hwr_ser_case_t wifi_steering_eventRegister_suite[] = {
	{ "cb_null",                       0,  1,   0, 0 },
	{ "cb_valid",                      1,  1,   0, 0 },
	{ "cb_dangling",                   2,  1,   0, 0 },
	{ "cb_null_two_calls",             0,  2,   0, 0 },
	{ "cb_valid_two_calls",            1,  2,   0, 0 },
	{ "cb_dangling_two_calls",         2,  2,   0, 0 },
	{ "cb_null_ten_calls",             0, 10,   0, 0 },
	{ "cb_valid_ten_calls",            1, 10,   0, 0 },
	{ "log_prefilled_1",               1,  1,   1, 0 },
	{ "log_prefilled_100",             1,  1, 100, 0 },
	{ "log_almost_full",               1,  1, 254, 0 },
	{ "log_full",                      1,  1, 255, 0 },
	{ "log_full_cb_null",              0,  1, 255, 0 },
	{ "log_full_cb_dangling",          2,  1, 255, 0 },
	{ NULL, 0, 0, 0, 0 }
};
