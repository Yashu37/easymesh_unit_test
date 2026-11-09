/*
 * UNIT TEST (input constructor): construct_int_wifi_getRadioChannel
 *
 * wifi_getRadioChannel(radioIndex, output_ulong) (platform/intel) looks the radio up by RDK index; for a radio that is configured AND enabled it stores
 * oper_param.channel through output_ulong and returns RETURN_OK, in every other case (no such radio, not configured, not enabled) it returns RETURN_ERR
 * and leaves the output alone.  The suite crosses: channels 0 / 1 / 6 / 11 / 13 / 36 / 100 / 149 / 165 / 255 / 256 / 65535 / UINT_MAX, radio index 0 / 1 / 2 /
 * -1 / INT_MIN / INT_MAX (the radio found, missing, or only another radio present), configured 0 / 1 x enable 0 / 1 / 2 / 0x80 / 0xFF (BOOL is unsigned char,
 * non-zero is true), the output NULL (only on paths that do not write it) / the runner's slot, and repeated calls.  The output is a ULONG inside a canary slab
 * whose head and tail are POISONED during the call, with a stale value; Checks: return value, *output_ulong == channel on success / the stale value
 * otherwise, the canary bytes, the guard slab, the log (the function does not log), one lookup per call with the same index.
 * Rows named invalid_* run last: a NULL output on a configured, enabled radio is written through (expected: RETURN_ERR, nothing written).
 * Row layout: see hwr_igc_case_t.
 */
#include <limits.h>
#include "hwr_igc.h"

#define OK   RETURN_OK
#define ERR  RETURN_ERR

/* name, radio_index, has_radio (0 none, 1 found, 2 other radio only), configured, enable, channel, out_mode, calls, expected_ret, last */
hwr_igc_case_t int_wifi_getRadioChannel_suite[] = {
	/* ---- success: configured and enabled ---- */
	{ "channel_0",                  0, 1, 1, 1,          0, 1, 1, OK, 0 },
	{ "channel_1",                  0, 1, 1, 1,          1, 1, 1, OK, 0 },
	{ "channel_6",                  0, 1, 1, 1,          6, 1, 1, OK, 0 },
	{ "channel_11",                 0, 1, 1, 1,         11, 1, 1, OK, 0 },
	{ "channel_13",                 0, 1, 1, 1,         13, 1, 1, OK, 0 },
	{ "channel_36",                 0, 1, 1, 1,         36, 1, 1, OK, 0 },
	{ "channel_100",                0, 1, 1, 1,        100, 1, 1, OK, 0 },
	{ "channel_149",                0, 1, 1, 1,        149, 1, 1, OK, 0 },
	{ "channel_165",                0, 1, 1, 1,        165, 1, 1, OK, 0 },
	{ "channel_255",                0, 1, 1, 1,        255, 1, 1, OK, 0 },
	{ "channel_256",                0, 1, 1, 1,        256, 1, 1, OK, 0 },
	{ "channel_65535",              0, 1, 1, 1,      65535, 1, 1, OK, 0 },
	{ "channel_uint_max",           0, 1, 1, 1,   UINT_MAX, 1, 1, OK, 0 },
	{ "enable_2_is_true",           0, 1, 1, 2,         44, 1, 1, OK, 0 },
	{ "enable_0x80_is_true",        0, 1, 1, 0x80,      48, 1, 1, OK, 0 },
	{ "enable_0xff_is_true",        0, 1, 1, 0xFF,      52, 1, 1, OK, 0 },
	/* ---- radio index ---- */
	{ "radio_1",                    1, 1, 1, 1,         36, 1, 1, OK, 0 },
	{ "radio_2",                    2, 1, 1, 1,        149, 1, 1, OK, 0 },
	{ "radio_negative_found",      -1, 1, 1, 1,          6, 1, 1, OK, 0 },
	{ "radio_int_min_found",  INT_MIN, 1, 1, 1,         11, 1, 1, OK, 0 },
	{ "radio_int_max_found",  INT_MAX, 1, 1, 1,         36, 1, 1, OK, 0 },
	{ "radio_missing",              0, 0, 1, 1,          6, 1, 1, ERR, 0 },
	{ "radio_other_index_only",     0, 2, 1, 1,          6, 1, 1, ERR, 0 },
	{ "radio_missing_int_max", INT_MAX, 0, 1, 1,         6, 1, 1, ERR, 0 },
	/* ---- not configured / not enabled ---- */
	{ "not_configured_enabled",     0, 1, 0, 1,          6, 1, 1, ERR, 0 },
	{ "configured_not_enabled",     0, 1, 1, 0,          6, 1, 1, ERR, 0 },
	{ "not_configured_not_enabled", 0, 1, 0, 0,          6, 1, 1, ERR, 0 },
	{ "not_configured_enable_0xff", 0, 1, 0, 0xFF,       6, 1, 1, ERR, 0 },
	/* ---- output NULL on paths that never write it ---- */
	{ "output_null_radio_missing",  0, 0, 1, 1,          6, 0, 1, ERR, 0 },
	{ "output_null_not_configured", 0, 1, 0, 1,          6, 0, 1, ERR, 0 },
	{ "output_null_not_enabled",    0, 1, 1, 0,          6, 0, 1, ERR, 0 },
	/* ---- repeated calls ---- */
	{ "two_calls_success",          0, 1, 1, 1,         36, 1, 2, OK, 0 },
	{ "ten_calls_success",          1, 1, 1, 1,        100, 1, 10, OK, 0 },
	{ "two_calls_error",            0, 1, 0, 1,         36, 1, 2, ERR, 0 },
	/* ---- invalid input that crashes the original (run last) ---- */
	{ "invalid_output_null_configured_enabled", 0, 1, 1, 1, 6, 0, 1, ERR, 1 },
	{ "invalid_output_null_radio_1",            1, 1, 1, 1, 36, 0, 1, ERR, 1 },
	{ NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};
