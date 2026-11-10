/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_setApWpsPin
 *
 * wifi_hal_setApWpsPin(ap_index, wps_pin).  Inputs crossed: wps_pin NULL / empty / 4 / 8 / 63 / 64 / 1000 characters (heap string of exactly that length) / non-digits;
 * ap_index 0, 1, 15, -1, INT_MAX, INT_MIN; the callee returning 0, -1, 1, -4, INT_MAX, INT_MIN (passed through unchanged); repeated calls; a log slot that is empty / holds text /
 * is almost full / is full.  A NULL pin must return -1 without calling the callee; any other pin is forwarded unchanged (same pointer, index as unsigned).
 */
#include "hwr_wpp.h"
#include <limits.h>

#define OK 0
#define ER -1
#define N -1
#define S -2
/* name, ap_index, pin_len, pin_text, callee_ret, calls, prefill, expected_ret */
hwr_wpp_case_t sg_wifi_hal_setApWpsPin_suite[] = {
	{ "pin_8_digits",             0,   8, NULL,       0, 1,   0, OK },
	{ "pin_8_digits_ap1",         1,   8, NULL,       0, 1,   0, OK },
	{ "pin_8_digits_ap15",       15,   8, NULL,       0, 1,   0, OK },
	{ "pin_4_digits",             0,   4, NULL,       0, 1,   0, OK },
	{ "pin_empty",                0,   0, NULL,       0, 1,   0, OK },
	{ "pin_1_char",               0,   1, NULL,       0, 1,   0, OK },
	{ "pin_63_chars",             0,  63, NULL,       0, 1,   0, OK },
	{ "pin_64_chars",             0,  64, NULL,       0, 1,   0, OK },
	{ "pin_1000_chars",           0,1000, NULL,       0, 1,   0, OK },
	{ "pin_text_not_digits",      0,   S, "abcdefgh", 0, 1,   0, OK },
	{ "pin_text_with_spaces",     0,   S, "12 34 56", 0, 1,   0, OK },
	{ "pin_text_percent_s",       0,   S, "%s%s%n",   0, 1,   0, OK },
	{ "callee_fails",             0,   8, NULL,      -1, 1,   0, -1 },
	{ "callee_returns_1",         0,   8, NULL,       1, 1,   0, 1 },
	{ "callee_returns_minus_4",   0,   8, NULL,      -4, 1,   0, -4 },
	{ "callee_returns_int_max",   0,   8, NULL, INT_MAX, 1,   0, INT_MAX },
	{ "callee_returns_int_min",   0,   8, NULL, INT_MIN, 1,   0, INT_MIN },
	{ "ap_minus_1",              -1,   8, NULL,       0, 1,   0, OK },
	{ "ap_int_max",         INT_MAX,   8, NULL,       0, 1,   0, OK },
	{ "ap_int_min",         INT_MIN,   8, NULL,       0, 1,   0, OK },
	{ "two_calls",                2,   8, NULL,       0, 2,   0, OK },
	{ "ten_calls",                2,   8, NULL,       0,10,   0, OK },
	{ "log_prefilled_100",        2,   8, NULL,       0, 1, 100, OK },
	{ "log_almost_full",          2,   8, NULL,       0, 1, 254, OK },
	{ "log_full",                 2,   8, NULL,       0, 1, 255, OK },
	{ "pin_1000_log_full",        2,1000, NULL,       0, 1, 255, OK },
	{ "pin_null",                 0,   N, NULL,       0, 1,   0, ER },
	{ "pin_null_callee_would_fail", 0, N, NULL,      -1, 1,   0, ER },
	{ "pin_null_callee_would_return_1", 0, N, NULL,   1, 1,   0, ER },
	{ "pin_null_ap_minus_1",     -1,   N, NULL,       0, 1,   0, ER },
	{ "pin_null_ap_int_max", INT_MAX,  N, NULL,       0, 1,   0, ER },
	{ "pin_null_two_calls",       3,   N, NULL,       0, 2,   0, ER },
	{ "pin_null_ten_calls",       3,   N, NULL,       0,10,   0, ER },
	{ "pin_null_log_full",        3,   N, NULL,       0, 1, 255, ER },
	{ NULL, 0, 0, NULL, 0, 0, 0, 0 }
};
