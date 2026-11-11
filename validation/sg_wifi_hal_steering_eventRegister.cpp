/*
 * HANDLER: wifi_hal_steering_eventRegister (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:4696-4708 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It stores the callback in the steering event slot of
 * the HAL device callbacks (replacing any earlier one; NULL clears it); it then registers nl80211_steering_event with the driver layer (wifi_steering_eventRegister, outside the HAL_IPC build) and returns 0, or RETURN_ERR when the callbacks table is not available.
 *
 * Scaffolding only: get_hal_device_callbacks is an accessor over the runner's world (the real one, wifi_hal.c:4764, returns the address of g_wifi_hal.callbacks); renamed
 * hwr_sg_wifi_hal_steering_eventRegister.
 */
#include "hwr_wse.h"
#include <stdio.h>
#include <string.h>

hwr_wse_world_t hwr_wse_world;
void hwr_wse_cb_a(UINT steeringgroupIndex, wifi_steering_event_t *event) { }
void hwr_wse_cb_b(UINT steeringgroupIndex, wifi_steering_event_t *event) { }
/* recording stubs: the real nl80211_steering_event is wifi_hal_nl80211.c:4529, wifi_steering_eventRegister is the platform/extender entry point */
extern "C" void nl80211_steering_event(UINT steeringgroupIndex, wifi_steering_event_t *event) { }
extern "C" INT wifi_steering_eventRegister(wifi_steering_eventCB_t event_cb) { hwr_wse_world.steer_calls++; hwr_wse_world.steer_arg = (void *)event_cb; return 0; }
#define get_hal_device_callbacks hwr_wse_get_hal_device_callbacks
#define wifi_hal_steering_eventRegister hwr_sg_wifi_hal_steering_eventRegister

extern "C" {
wifi_device_callbacks_t *get_hal_device_callbacks()
{
    hwr_wse_world.accessor_calls++;
    return hwr_wse_world.no_cbs ? NULL : &hwr_wse_world.cbs;
}

/* --- wifi_hal.c:4696-4708 --- */
INT wifi_hal_steering_eventRegister(wifi_steering_eventCB_t event_cb)
{
    wifi_device_callbacks_t *callbacks;
    callbacks = get_hal_device_callbacks();
    if (callbacks == NULL) {
        return RETURN_ERR;
    }
    callbacks->steering_event_callback = event_cb;
#ifndef HAL_IPC
    wifi_steering_eventRegister(nl80211_steering_event);
#endif
    return 0;
}
}
