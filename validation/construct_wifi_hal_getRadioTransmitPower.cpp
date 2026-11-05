/*
 * UNIT TEST (input constructor): construct_wifi_hal_getRadioTransmitPower
 *
 * wifi_hal_getRadioTransmitPower(radioIndex, output_ulong) is a thin wrapper: it logs and calls the platform
 * function wifi_getRadioTransmitPower(radioIndex, output_ulong) (the platform fills *output_ulong on success and
 * returns RETURN_ERR for an unknown radio or a driver error), and returns 0 whatever the platform answered.
 *
 * Stub (below): hwr_gtp_platform records its arguments, returns the configured result and, on success, writes the
 * configured power through the pointer (a NULL pointer crashes there, like the real platform code).
 * Inputs crossed: radio indexes 0, 1, 2, 3, -1, INT_MIN, INT_MAX forwarded unchanged; powers 0, 1, 17, 20, 30, 100,
 * ULONG_MAX; platform failures (-1, 1, 255, INT_MIN) which must be reported and leave *output_ulong untouched;
 * repeated calls; the log; and a NULL output_ulong (crashes the unfixed function when the platform succeeds:
 * forked rows; with a failing platform the unfixed function returns 0).  Expected result is the SAFE contract: a
 * failing platform query is reported as RETURN_ERR with the output untouched.  A FAIL is a finding.
 */
#include <limits.h>
#include "hwr_gtp.h"

hwr_gtp_rec_t hwr_gtp_rec;
static int g_ret; static unsigned long g_power;

void hwr_gtp_configure(int callee_ret, unsigned long power) { memset(&hwr_gtp_rec, 0, sizeof(hwr_gtp_rec)); g_ret = callee_ret; g_power = power; }
extern "C" INT hwr_gtp_platform(INT radioIndex, ULONG *tx_power)
{
	hwr_gtp_rec.calls++; hwr_gtp_rec.radio = radioIndex; hwr_gtp_rec.out = tx_power;
	if (g_ret == 0) *tx_power = g_power;                  /* the real platform code writes through the pointer */
	return g_ret;
}

#define E RETURN_ERR
/* name, radio, null_out, callee_ret, power, calls, check_log, expected_ret, forked */
hwr_gtp_case_t wifi_hal_getRadioTransmitPower_suite[] = {
	/* ---- platform succeeds ---- */
	{ "radio_0_power_20",            0, 0, 0, 20, 1, 0, 0, 0 },
	{ "radio_1_power_17",            1, 0, 0, 17, 1, 0, 0, 0 },
	{ "radio_2_power_30",            2, 0, 0, 30, 1, 0, 0, 0 },
	{ "radio_3_power_100",           3, 0, 0, 100, 1, 0, 0, 0 },
	{ "power_0",                     0, 0, 0, 0, 1, 0, 0, 0 },
	{ "power_1",                     0, 0, 0, 1, 1, 0, 0, 0 },
	{ "power_ulong_max",             0, 0, 0, ULONG_MAX, 1, 0, 0, 0 },
	{ "radio_minus_1_forwarded",     -1, 0, 0, 20, 1, 0, 0, 0 },
	{ "radio_int_min_forwarded",     INT_MIN, 0, 0, 20, 1, 0, 0, 0 },
	{ "radio_int_max_forwarded",     INT_MAX, 0, 0, 20, 1, 0, 0, 0 },
	{ "repeated_calls_x3",           1, 0, 0, 23, 3, 0, 0, 0 },
	{ "log_has_function_name_and_enter", 0, 0, 0, 20, 1, 1, 0, 0 },
	/* ---- platform fails: the failure must be reported, *output_ulong untouched ---- */
	{ "platform_fails_minus_1",      0, 0, -1, 20, 1, 0, E, 0 },
	{ "platform_fails_1",            0, 0, 1, 20, 1, 0, E, 0 },
	{ "platform_fails_255",          1, 0, 255, 20, 1, 0, E, 0 },
	{ "platform_fails_int_min",      2, 0, INT_MIN, 20, 1, 0, E, 0 },
	{ "platform_fails_unknown_radio_7", 7, 0, -1, 20, 1, 0, E, 0 },
	{ "platform_fails_radio_minus_1", -1, 0, -1, 20, 1, 0, E, 0 },
	{ "platform_fails_radio_int_max", INT_MAX, 0, -1, 20, 1, 0, E, 0 },
	{ "platform_fails_repeated_x3",  1, 0, -1, 20, 3, 0, E, 0 },
	/* ---- NULL output_ulong: the platform writes through it ---- */
	{ "output_null_radio_0",         0, 1, 0, 20, 1, 0, E, 1 },
	{ "output_null_radio_1",         1, 1, 0, 17, 1, 0, E, 1 },
	{ "output_null_power_0",         0, 1, 0, 0, 1, 0, E, 1 },
	{ "output_null_power_ulong_max", 2, 1, 0, ULONG_MAX, 1, 0, E, 1 },
	{ "output_null_platform_fails",  0, 1, -1, 20, 1, 0, E, 0 },
	{ NULL, 0, 0, 0, 0, 0, 0, 0, 0 }
};
