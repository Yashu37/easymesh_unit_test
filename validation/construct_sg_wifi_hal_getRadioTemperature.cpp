/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_getRadioTemperature
 *
 * wifi_hal_getRadioTemperature(radioIndex, radioPhyTemperature).  Inputs crossed: radioIndex 0 / 1 / 2 / 255 / UINT_MAX (forwarded to the platform); radioPhyTemperature an exact 4-byte heap block / NULL; the
 * platform function present / absent; the platform function returning 0 / 1 / -1 / INT_MIN and writing or not writing the temperature (0 / 45 / UINT_MAX).  Expected (CORRECT behaviour): NULL
 * radioPhyTemperature -> RETURN_ERR (whether the platform is still called is not prescribed); no platform function -> RETURN_ERR; a negative platform result -> RETURN_ERR; otherwise RETURN_OK with the output exactly as the platform left it
 * (radioIndex and the pointer forwarded unchanged); the function only reads the output. Rows with last = 1 break the original: they run LAST.
 */
#include "hwr_wrt.h"
#include <limits.h>

/* name, radio_index, out_null, no_fn, fn_ret, write_temp, temp_value, last */
hwr_wrt_case_t sg_wifi_hal_getRadioTemperature_suite[] = {
	{ "radio0_temp_45",            0, 0, 0, 0, 1, 45, 0 },
	{ "radio1_temp_0",             1, 0, 0, 0, 1, 0, 0 },
	{ "radio2_temp_uint_max",      2, 0, 0, 0, 1, UINT_MAX, 0 },
	{ "radio255_forwarded",        255, 0, 0, 0, 1, 61, 0 },
	{ "radio_uint_max_forwarded",  UINT_MAX, 0, 0, 0, 1, 61, 0 },
	{ "platform_returns_1_ok",     0, 0, 0, 1, 1, 50, 0 },
	{ "platform_does_not_write_output", 0, 0, 0, 0, 0, 0, 0 },
	{ "platform_returns_minus1",   0, 0, 0, -1, 1, 45, 0 },
	{ "platform_returns_int_min",  1, 0, 0, INT_MIN, 0, 0, 0 },
	{ "no_platform_function",      0, 0, 1, 0, 1, 45, 0 },
	{ "no_platform_function_radio_big", UINT_MAX, 0, 1, 0, 0, 0, 0 },
	{ "out_null_no_platform_function",  0, 1, 1, 0, 0, 0, 0 },
	{ "out_null_platform_returns_minus1", 0, 1, 0, -1, 0, 0, 0 },
	{ "out_null_platform_returns_0",    0, 1, 0, 0, 0, 0, 1 },
	{ "out_null_platform_returns_1",    1, 1, 0, 1, 1, 45, 1 },
	{ NULL }
};
