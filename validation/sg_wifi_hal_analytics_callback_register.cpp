/*
 * HANDLER: wifi_hal_analytics_callback_register (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:4656-4667 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It stores the callback in the analytics slot of
 * the HAL device callbacks (replacing any earlier one; NULL clears it); it returns RETURN_OK, or RETURN_ERR when the callbacks table is not available.
 *
 * Scaffolding only: get_hal_device_callbacks is an accessor over the runner's world (the real one, wifi_hal.c:4764, returns the address of g_wifi_hal.callbacks); renamed
 * hwr_sg_wifi_hal_analytics_callback_register.
 */
#include "hwr_wan.h"
#include <stdio.h>
#include <string.h>

hwr_wan_world_t hwr_wan_world;
INT hwr_wan_cb_a(CHAR *fmt, ...) { return 1; }
INT hwr_wan_cb_b(CHAR *fmt, ...) { return 2; }
#define get_hal_device_callbacks hwr_wan_get_hal_device_callbacks
#define wifi_hal_analytics_callback_register hwr_sg_wifi_hal_analytics_callback_register

extern "C" {
wifi_device_callbacks_t *get_hal_device_callbacks()
{
    hwr_wan_world.accessor_calls++;
    return hwr_wan_world.no_cbs ? NULL : &hwr_wan_world.cbs;
}

/* --- wifi_hal.c:4656-4667 --- */
INT wifi_hal_analytics_callback_register(wifi_analytics_callback l_callback_cb)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();
    if (callbacks == NULL) {
       return RETURN_ERR;
    }

    callbacks->analytics_callback = l_callback_cb;
    return RETURN_OK;
}
}
