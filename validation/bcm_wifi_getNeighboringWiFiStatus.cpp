/*
 * HANDLER: wifi_getNeighboringWiFiStatus (platform/broadcom)
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/broadcom/platform.c:412-431 (~/Desktop/G/rdk-wifi-hal), without its
 * #if defined WIFI_EMULATOR_CHANGE block (the emulator branch is not compiled on a Broadcom build).  This file holds the ORIGINAL code: no fix applied.
 * It is a thin wrapper: it calls wifi_hal_getNeighboringWiFiStatus (src/wifi_hal.c:3691), whose logic is covered by the banana-pi
 * wifi_getNeighboringWiFiStatus harness (the same core function), forwards WIFI_HAL_NOT_READY unchanged, logs RETURN_ERR and returns the core result.
 *
 * Scaffolding only: wifi_hal_getNeighboringWiFiStatus (renamed hwr_bgn_core_getNeighboringWiFiStatus by a macro, the real name is stubbed by ipc_server_output) is a recording stub whose return value the runner sets; the print macro is mapped to the log
 * sink hwr_print (runner-poisoned slot).  Renamed hwr_bcm_wifi_getNeighboringWiFiStatus because the banana-pi harness uses the real name.
 */
#include "hwr_bgn.h"

#define wifi_hal_stats_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define wifi_getNeighboringWiFiStatus hwr_bcm_wifi_getNeighboringWiFiStatus
#define wifi_hal_getNeighboringWiFiStatus hwr_bgn_core_getNeighboringWiFiStatus

hwr_bgn_world_t hwr_bgn_world;

static INT wifi_hal_getNeighboringWiFiStatus(INT radio_index, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *output_array_size)
{
	hwr_bgn_world.calls++;
	hwr_bgn_world.last_radio = radio_index;
	hwr_bgn_world.last_array = neighbor_ap_array;
	hwr_bgn_world.last_size = output_array_size;
	return hwr_bgn_world.ret;
}

/* --- platform.c:412-431 --- */
extern "C" {
INT wifi_getNeighboringWiFiStatus(INT radio_index, wifi_neighbor_ap2_t **neighbor_ap_array,
    UINT *output_array_size)
{
    int ret;
    ret = wifi_hal_getNeighboringWiFiStatus(radio_index, neighbor_ap_array, output_array_size);
    if (ret == WIFI_HAL_NOT_READY) {
        return ret;
    } else if (ret == RETURN_ERR) {
        wifi_hal_stats_error_print("%s:%d: wifi_hal_getNeighboringWiFiStatus failed\n", __func__,
            __LINE__);
    }
    return ret;
}
}
