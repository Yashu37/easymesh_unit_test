/*
 * HANDLER: wifi_getNASta (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:5022-5039 (~/Desktop/G/rdk-wifi-hal), compiled with MXL_WIFI defined (the build that has logic; without it the function only casts its arguments to
 * void and returns WIFI_HAL_ERROR).  This file holds the ORIGINAL code (no fixes).  With MXL_WIFI: apIndex outside 0 .. MAX_VAP-1 -> WIFI_HAL_INVALID_ARGUMENTS (AP_INDEX_ASSERT), NULL params or NULL sta_info ->
 * WIFI_HAL_ERROR, otherwise the result of platform_get_nasta(apIndex, params, sta_info).
 *
 * Scaffolding only: AP_INDEX_ASSERT / AP_INDEX_ASSERT_RC copied from wifi_hal.c:74-93; platform_get_nasta is a recording stub; the print macro goes to the log sink hwr_print; renamed hwr_sg_wifi_getNASta.
 */
#include "hwr_wns.h"
#include <stdio.h>
#include <string.h>

#define MXL_WIFI 1
hwr_wns_world_t hwr_wns_world;
#define wifi_hal_error_print(format, ...) hwr_print(1, format, ##__VA_ARGS__)
#define wifi_getNASta hwr_sg_wifi_getNASta
/* wifi_hal.c:74-82, 93 */
#define AP_INDEX_ASSERT_RC(apIndex, retcode) \
    do { \
        int _index = (int)apIndex; \
        if ((_index >= (MAX_VAP)) || (_index < 0)) { \
            wifi_hal_error_print("%s, INCORRECT apIndex = %d MAX_VAP = %d\n", __FUNCTION__, \
                            _index, MAX_VAP); \
            return retcode; \
        } \
    } while (0)
#define AP_INDEX_ASSERT(apIndex)        AP_INDEX_ASSERT_RC(apIndex, WIFI_HAL_INVALID_ARGUMENTS)
static int platform_get_nasta(INT apIndex, const wifi_na_sta_req_params_t *params, wifi_na_sta_info_t *sta_info)
{
	hwr_wns_world_t *w = &hwr_wns_world;
	w->calls++; w->call_ap = apIndex; w->call_params = params; w->call_info = sta_info;
	if (w->write_info && sta_info != NULL) sta_info->rcpi = 120;
	return w->fn_ret;
}

/* --- wifi_hal.c:5022-5039 --- */
INT wifi_getNASta(INT apIndex, const wifi_na_sta_req_params_t *params, wifi_na_sta_info_t *sta_info)
{
#ifdef MXL_WIFI
    AP_INDEX_ASSERT(apIndex);

    if (!params || !sta_info) {
        wifi_hal_error_print("%s:%d: Invalid parameters\n", __func__, __LINE__);
        return WIFI_HAL_ERROR;
    }

    return platform_get_nasta(apIndex, params, sta_info);
#else
    (void)apIndex;
    (void)params;
    (void)sta_info;
    return WIFI_HAL_ERROR;
#endif /* MXL_WIFI */
}
