/*
 * HANDLER: wifi_hal_staConnectionStatus_callback_register (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:4614-4626 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It stores the callback in the STA connection-status slot of
 * the HAL device callbacks (replacing any earlier one; NULL clears it); it returns void and does nothing when the callbacks table is not available.
 *
 * Scaffolding only: get_hal_device_callbacks is an accessor over the runner's world (the real one, wifi_hal.c:4764, returns the address of g_wifi_hal.callbacks); renamed
 * hwr_sg_wifi_hal_staConnectionStatus_callback_register.
 */
#include "hwr_wcs.h"
#include <stdio.h>
#include <string.h>

hwr_wcs_world_t hwr_wcs_world;
INT hwr_wcs_cb_a(INT apIndex, wifi_bss_info_t *bss_dev, wifi_station_stats_t *sta) { return 1; }
INT hwr_wcs_cb_b(INT apIndex, wifi_bss_info_t *bss_dev, wifi_station_stats_t *sta) { return 2; }
#define get_hal_device_callbacks hwr_wcs_get_hal_device_callbacks
#define wifi_hal_staConnectionStatus_callback_register hwr_sg_wifi_hal_staConnectionStatus_callback_register

extern "C" {
wifi_device_callbacks_t *get_hal_device_callbacks()
{
    hwr_wcs_world.accessor_calls++;
    return hwr_wcs_world.no_cbs ? NULL : &hwr_wcs_world.cbs;
}

/* --- wifi_hal.c:4614-4626 --- */
void wifi_hal_staConnectionStatus_callback_register(wifi_staConnectionStatus_callback func)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();
    if (callbacks == NULL) {
        return;
    }

    callbacks->sta_conn_status_callback = func;

    return;
}
}
