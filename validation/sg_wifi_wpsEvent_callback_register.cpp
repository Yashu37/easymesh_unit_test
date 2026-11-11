/*
 * HANDLER: wifi_wpsEvent_callback_register (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:4642-4654 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It stores the callback in the WPS event slot of
 * the HAL device callbacks (replacing any earlier one; NULL clears it); it returns RETURN_OK, or RETURN_ERR when the callbacks table is not available.
 *
 * Scaffolding only: get_hal_device_callbacks is an accessor over the runner's world (the real one, wifi_hal.c:4764, returns the address of g_wifi_hal.callbacks); renamed
 * hwr_sg_wifi_wpsEvent_callback_register.
 */
#include "hwr_wpe.h"
#include <stdio.h>
#include <string.h>

hwr_wpe_world_t hwr_wpe_world;
INT hwr_wpe_cb_a(INT apIndex, wifi_wps_ev_t event) { return 1; }
INT hwr_wpe_cb_b(INT apIndex, wifi_wps_ev_t event) { return 2; }
#define get_hal_device_callbacks hwr_wpe_get_hal_device_callbacks
#define wifi_wpsEvent_callback_register hwr_sg_wifi_wpsEvent_callback_register

extern "C" {
wifi_device_callbacks_t *get_hal_device_callbacks()
{
    hwr_wpe_world.accessor_calls++;
    return hwr_wpe_world.no_cbs ? NULL : &hwr_wpe_world.cbs;
}

/* --- wifi_hal.c:4642-4654 --- */
INT wifi_wpsEvent_callback_register(wifi_wpsEvent_callback func)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();
    if (callbacks == NULL) {
        return RETURN_ERR;
    }

    callbacks->wps_event_callback = func;

    return RETURN_OK;
}
}
