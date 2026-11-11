/*
 * HANDLER: wifi_hal_mgmt_frame_callbacks_register (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:4420-4430 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It stores the callback in the management-frame receive slot of
 * the HAL device callbacks (replacing any earlier one; NULL clears it) and returns 0, or RETURN_ERR when the callbacks table is not available.
 *
 * Scaffolding only: get_hal_device_callbacks is an accessor over the runner's world (the real one, wifi_hal.c:4764, returns the address of g_wifi_hal.callbacks); renamed
 * hwr_sg_wifi_hal_mgmt_frame_callbacks_register.
 */
#include "hwr_wmc.h"
#include <stdio.h>
#include <string.h>

hwr_wmc_world_t hwr_wmc_world;
int hwr_wmc_cb_a(INT ap_index, mac_address_t sta_mac, UCHAR *frame, UINT len, wifi_mgmtFrameType_t type, wifi_direction_t dir) { return 1; }
int hwr_wmc_cb_b(INT ap_index, mac_address_t sta_mac, UCHAR *frame, UINT len, wifi_mgmtFrameType_t type, wifi_direction_t dir) { return 2; }
#define get_hal_device_callbacks hwr_wmc_get_hal_device_callbacks
#define wifi_hal_mgmt_frame_callbacks_register hwr_sg_wifi_hal_mgmt_frame_callbacks_register

extern "C" {
wifi_device_callbacks_t *get_hal_device_callbacks()
{
    hwr_wmc_world.accessor_calls++;
    return hwr_wmc_world.no_cbs ? NULL : &hwr_wmc_world.cbs;
}

/* --- wifi_hal.c:4420-4430 --- */
INT wifi_hal_mgmt_frame_callbacks_register(wifi_receivedMgmtFrame_callback func)
{
    wifi_device_callbacks_t *callbacks;
    callbacks = get_hal_device_callbacks();
    if (callbacks == NULL) {
        return RETURN_ERR;
    }
    callbacks->mgmt_frame_rx_callback = func;

    return 0;
}
}
