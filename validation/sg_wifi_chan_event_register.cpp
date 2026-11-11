/*
 * HANDLER: wifi_chan_event_register (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:4669-4680 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It stores the callback in the channel-change event slot of
 * the HAL device callbacks (replacing any earlier one; NULL clears it); it returns RETURN_OK, or RETURN_ERR when the callbacks table is not available.
 *
 * Scaffolding only: get_hal_device_callbacks is an accessor over the runner's world (the real one, wifi_hal.c:4764, returns the address of g_wifi_hal.callbacks); renamed
 * hwr_sg_wifi_chan_event_register.
 */
#include "hwr_wce.h"
#include <stdio.h>
#include <string.h>

hwr_wce_world_t hwr_wce_world;
void hwr_wce_cb_a(wifi_channel_change_event_t radio_channel_param) { }
void hwr_wce_cb_b(wifi_channel_change_event_t radio_channel_param) { }
#define get_hal_device_callbacks hwr_wce_get_hal_device_callbacks
#define wifi_chan_event_register hwr_sg_wifi_chan_event_register

extern "C" {
wifi_device_callbacks_t *get_hal_device_callbacks()
{
    hwr_wce_world.accessor_calls++;
    return hwr_wce_world.no_cbs ? NULL : &hwr_wce_world.cbs;
}

/* --- wifi_hal.c:4669-4680 --- */
INT wifi_chan_event_register(wifi_chan_event_CB_t event_cb)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();
    if (callbacks == NULL) {
       return RETURN_ERR;
    }

    callbacks->channel_change_event_callback = event_cb;
    return RETURN_OK;
}
}
