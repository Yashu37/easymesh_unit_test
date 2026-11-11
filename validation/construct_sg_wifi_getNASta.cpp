/*
 * UNIT TEST (input constructor): construct_sg_wifi_getNASta
 *
 * wifi_getNASta(apIndex, params, sta_info) (MXL_WIFI build).  Inputs crossed: apIndex 0 / 1 / MAX_VAP-1 (valid) and -1 / MAX_VAP / MAX_VAP+1 / INT_MAX / INT_MIN (invalid); params an exact heap block / NULL;
 * sta_info an exact heap block / NULL; platform_get_nasta returning 0 / -1 / 1 / WIFI_HAL_ERROR and filling or not filling sta_info.  Expected (CORRECT behaviour): invalid apIndex ->
 * WIFI_HAL_INVALID_ARGUMENTS and the platform not called; NULL params or NULL sta_info (valid apIndex) -> WIFI_HAL_ERROR and the platform not called; otherwise the platform is called exactly once with the
 * unchanged arguments and its result is returned, the wrapper never reads params nor writes sta_info itself.  No crash case is expected.
 */
#include "hwr_wns.h"
#include <limits.h>

/* name, ap_index, params_null, info_null, fn_ret, write_info, last */
hwr_wns_case_t sg_wifi_getNASta_suite[] = {
	{ "ap0_success",               0, 0, 0, 0, 1, 0 },
	{ "ap1_success",               1, 0, 0, 0, 1, 0 },
	{ "ap_last_valid_success",     MAX_VAP - 1, 0, 0, 0, 1, 0 },
	{ "platform_returns_error",    0, 0, 0, WIFI_HAL_ERROR, 0, 0 },
	{ "platform_returns_minus1",   1, 0, 0, -1, 0, 0 },
	{ "platform_returns_1",        0, 0, 0, 1, 1, 0 },
	{ "platform_does_not_fill",    0, 0, 0, 0, 0, 0 },
	{ "params_null",               0, 1, 0, 0, 1, 0 },
	{ "sta_info_null",             0, 0, 1, 0, 1, 0 },
	{ "both_null",                 1, 1, 1, 0, 1, 0 },
	{ "ap_minus1_invalid",         -1, 0, 0, 0, 1, 0 },
	{ "ap_max_vap_invalid",        MAX_VAP, 0, 0, 0, 1, 0 },
	{ "ap_max_vap_plus1_invalid",  MAX_VAP + 1, 0, 0, 0, 1, 0 },
	{ "ap_int_max_invalid",        INT_MAX, 0, 0, 0, 1, 0 },
	{ "ap_int_min_invalid",        INT_MIN, 0, 0, 0, 1, 0 },
	{ "ap_invalid_and_null_args",  -1, 1, 1, 0, 0, 0 },
	{ NULL }
};
