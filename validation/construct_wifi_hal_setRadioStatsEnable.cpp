/*
 * UNIT TEST (input constructor): construct_wifi_hal_setRadioStatsEnable
 *
 * wifi_hal_setRadioStatsEnable(radioIndex, enabled) is the HAL IPC server wrapper for
 * wifi_setRadioStatsEnable.  In rdk-wifi-hal it is an EMPTY function: it logs two debug lines and returns 0
 * for every input.  Nothing can be observed except the return value, the log text and that it touches no
 * other memory, so the cases check exactly that over the parameter space:
 *   radioIndex : INT_MIN, -1000, -1, 0, 1, 2, 3, 15, 16, 255, 65536, INT_MAX
 *   enabled    : 0, 1, 2, 127, 128, 255 (BOOL is an unsigned char)
 * (every radioIndex x {0, 1}, plus every enabled value at radio 0 and at INT_MIN), repeated calls and the
 * log content.  Expected result is the SAFE contract (return 0, log "Enter", no memory touched), so a FAIL
 * is a finding.
 */
#include <stdarg.h>
#include <limits.h>
#include "hwr_defs.h"
#include "hwr_setRadioStatsEnable.h"


#define C(n, r, e)  { n, r, e, 1, 0 }
hwr_srse_case_t wifi_hal_setRadioStatsEnable_suite[] = {
	C("radio_int_min_disable",  INT_MIN, 0), C("radio_int_min_enable",  INT_MIN, 1),
	C("radio_m1000_disable",   -1000, 0),    C("radio_m1000_enable",   -1000, 1),
	C("radio_m1_disable",      -1, 0),       C("radio_m1_enable",      -1, 1),
	C("radio_0_disable",        0, 0),       C("radio_0_enable",        0, 1),
	C("radio_1_disable",        1, 0),       C("radio_1_enable",        1, 1),
	C("radio_2_disable",        2, 0),       C("radio_2_enable",        2, 1),
	C("radio_3_disable",        3, 0),       C("radio_3_enable",        3, 1),
	C("radio_15_disable",      15, 0),       C("radio_15_enable",      15, 1),
	C("radio_16_disable",      16, 0),       C("radio_16_enable",      16, 1),
	C("radio_255_disable",    255, 0),       C("radio_255_enable",    255, 1),
	C("radio_65536_disable", 65536, 0),      C("radio_65536_enable", 65536, 1),
	C("radio_int_max_disable", INT_MAX, 0),  C("radio_int_max_enable", INT_MAX, 1),
	C("enabled_2_radio0",       0, 2),       C("enabled_127_radio0",    0, 127),
	C("enabled_128_radio0",     0, 128),     C("enabled_255_radio0",    0, 255),
	C("enabled_255_radio_int_min", INT_MIN, 255), C("enabled_2_radio_int_max", INT_MAX, 2),
	{ "repeated_calls_x2_same_result",  0, 1, 2, 0 },
	{ "repeated_calls_x5_alternating",  1, 0, 5, 1 },
	{ "log_has_enter_and_function_name", 0, 1, 1, 2 },
	{ "log_empty_function_notice",      0, 0, 1, 3 },
	{ NULL, 0, 0, 0, 0 }
};
