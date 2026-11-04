/*
 * UNIT TEST (input constructor): construct_wifi_hal_getRadioChannelStats
 *
 * wifi_hal_getRadioChannelStats(radioIndex, input_output_channelStats_array, array_size) is the HAL IPC
 * server wrapper for the platform function wifi_getRadioChannelStats: it logs, truncates array_size to
 * HAL_IPC_RADIO_CHANNELS_MAX (64) when it is larger and forwards the call, returning the platform result.
 *
 * The platform function is a stub (below): it records its arguments, writes `array_size` entries of the
 * array (pattern 0x5A, like the real get_channel_stats fills one entry per channel) and returns a
 * configurable value.  The runner's array has room for exactly 64 entries and a poisoned tail behind it, so
 * an un-truncated size is an ASan use-after-poison.
 * Inputs crossed: array_size INT_MIN, -1000, -1, 0, 1, 2, 16, 63, 64, 65, 100, 1000, INT_MAX; radioIndex
 * -1 / 0 / 1 / 15 / INT_MAX; platform result 0 / -1 / other; NULL array (forked); repeated calls and the log.
 * Expected result is the SAFE contract: a NULL array or array_size <= 0 is rejected (RETURN_ERR, the
 * platform function is not called), sizes above 64 are truncated to 64, the platform result is returned.
 * A FAIL is a finding.
 */
#include <limits.h>
#include "hwr_grc.h"

hwr_grc_rec_t hwr_grc_rec;
static int g_ret;

extern "C" INT wifi_getRadioChannelStats(INT radioIndex, wifi_channelStats_t *input_output_channelStats_array, INT array_size)
{
	hwr_grc_rec.calls++; hwr_grc_rec.radio = radioIndex; hwr_grc_rec.arr = input_output_channelStats_array; hwr_grc_rec.size = array_size;
	for (INT i = 0; i < array_size; i++) memset(&input_output_channelStats_array[i], 0x5A, sizeof(wifi_channelStats_t));
	return g_ret;
}
void hwr_grc_configure(int callee_ret) { g_ret = callee_ret; memset(&hwr_grc_rec, 0, sizeof(hwr_grc_rec)); }

/* name, radio, array_size, callee_ret, null_arr, calls, check_log, expected_ret, expected_fwd, forked */
#define SZ(n, sz, fwd, ret)  { "size_" n, 0, sz, 0, 0, 1, 0, ret, fwd, 0 }
hwr_grc_case_t wifi_hal_getRadioChannelStats_suite[] = {
	SZ("int_min", INT_MIN, -1, -1), SZ("m1000", -1000, -1, -1), SZ("m1", -1, -1, -1), SZ("0", 0, -1, -1),
	SZ("1", 1, 1, 0), SZ("2", 2, 2, 0), SZ("16", 16, 16, 0), SZ("63", 63, 63, 0), SZ("64_max", 64, 64, 0),
	SZ("65_truncated", 65, 64, 0), SZ("100_truncated", 100, 64, 0), SZ("1000_truncated", 1000, 64, 0),
	SZ("int_max_truncated", INT_MAX, 64, 0),
	{ "radio_m1_size_8",            -1, 8, 0, 0, 1, 0, 0, 8, 0 },
	{ "radio_1_size_8",              1, 8, 0, 0, 1, 0, 0, 8, 0 },
	{ "radio_15_size_8",            15, 8, 0, 0, 1, 0, 0, 8, 0 },
	{ "radio_int_max_size_8",  INT_MAX, 8, 0, 0, 1, 0, 0, 8, 0 },
	{ "radio_int_min_size_8",  INT_MIN, 8, 0, 0, 1, 0, 0, 8, 0 },
	{ "platform_ret_m1_size_8",      0, 8, -1, 0, 1, 0, -1, 8, 0 },
	{ "platform_ret_1_size_8",       0, 8, 1, 0, 1, 0, 1, 8, 0 },
	{ "platform_ret_int_min_size_8", 0, 8, INT_MIN, 0, 1, 0, INT_MIN, 8, 0 },
	{ "platform_ret_m1_size_64",     0, 64, -1, 0, 1, 0, -1, 64, 0 },
	{ "platform_ret_m1_size_1000",   0, 1000, -1, 0, 1, 0, -1, 64, 0 },
	{ "repeated_calls_x3",           0, 10, 0, 0, 3, 0, 0, 10, 0 },
	{ "repeated_calls_x3_truncated", 0, 500, 0, 0, 3, 0, 0, 64, 0 },
	{ "log_has_size",                0, 12, 0, 0, 1, 1, 0, 12, 0 },
	{ "log_truncate_notice",         0, 200, 0, 0, 1, 2, 0, 64, 0 },
	/* ---- crash group (forked): NULL array reaches the platform function ---- */
	{ "crash_array_null_size_1",     0, 1, 0, 1, 1, 0, -1, -1, 1 },
	{ "crash_array_null_size_8",     0, 8, 0, 1, 1, 0, -1, -1, 1 },
	{ "crash_array_null_size_64",    0, 64, 0, 1, 1, 0, -1, -1, 1 },
	{ "crash_array_null_size_1000",  0, 1000, 0, 1, 1, 0, -1, -1, 1 },
	{ "array_null_size_0",           0, 0, 0, 1, 1, 0, -1, -1, 0 },
	{ NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};
