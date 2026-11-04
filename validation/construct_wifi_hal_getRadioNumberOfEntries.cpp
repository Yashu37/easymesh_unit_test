/*
 * UNIT TEST (input constructor): construct_wifi_hal_getRadioNumberOfEntries
 *
 * wifi_hal_getRadioNumberOfEntries(output) stores g_wifi_hal.num_radios (unsigned int) in *output (ULONG) and
 * returns 0.
 *
 * Inputs crossed: num_radios 0, 1, 2, 3, 4, 8, 255, 256, 65535, INT_MAX, 0x80000000 and UINT_MAX (the 32-bit
 * value must be widened to ULONG without sign extension), an output preset to 0 or to a garbage pattern (it must be
 * overwritten completely, all sizeof(ULONG) bytes), repeated calls, the log, and a NULL output (forked, so the
 * SEGV is visible but does not stop the run).  Expected result is the SAFE contract, so a FAIL is a finding.
 */
#include <limits.h>
#include "hwr_grn.h"

/* name, num_radios, null_out, calls, check_log, preset, expected_ret, expected_out, forked */
#define N(n, v)  { "num_radios_" n, v, 0, 1, 0, 0, 0, v, 0 }
#define NG(n, v) { "num_radios_" n "_garbage_preset", v, 0, 1, 0, 1, 0, v, 0 }
hwr_grn_case_t wifi_hal_getRadioNumberOfEntries_suite[] = {
	N("0", 0), N("1", 1), N("2", 2), N("3", 3), N("4", 4), N("8", 8), N("255", 255), N("256", 256), N("65535", 65535),
	N("int_max", INT_MAX), N("0x80000000", 0x80000000u), N("uint_max", UINT_MAX),
	NG("0", 0), NG("1", 1), NG("2", 2), NG("3", 3), NG("uint_max", UINT_MAX), NG("0x80000000", 0x80000000u),
	{ "repeated_calls_x3_same_result",      2, 0, 3, 0, 0, 0, 2, 0 },
	{ "repeated_calls_x3_garbage_preset",   3, 0, 3, 0, 1, 0, 3, 0 },
	{ "log_has_function_name_and_enter",    2, 0, 1, 1, 0, 0, 2, 0 },
	/* ---- crash group (forked): NULL output ---- */
	{ "crash_output_null_2_radios",         2, 1, 1, 0, 0, -1, 0, 1 },
	{ "crash_output_null_0_radios",         0, 1, 1, 0, 0, -1, 0, 1 },
	{ "crash_output_null_3_radios",         3, 1, 1, 0, 0, -1, 0, 1 },
	{ NULL, 0, 0, 0, 0, 0, 0, 0, 0 }
};
