/*
 * HANDLER: wifi_hal_ap_max_client_rejection_callback_register (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:4487-4498 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It stores the callback in the max-client-rejection slot of
 * the HAL device callbacks (replacing any earlier one; NULL clears it); it returns void and does nothing when the callbacks table is not available.
 *
 * Scaffolding only: get_hal_device_callbacks is an accessor over the runner's world (the real one, wifi_hal.c:4764, returns the address of g_wifi_hal.callbacks); renamed
 * hwr_sg_wifi_hal_ap_max_client_rejection_callback_register.
 */
#include "hwr_wmx.h"
#include <stdio.h>
#include <string.h>

hwr_wmx_world_t hwr_wmx_world;
INT hwr_wmx_cb_a(INT apIndex, char *MAC, INT reason) { return 1; }
INT hwr_wmx_cb_b(INT apIndex, char *MAC, INT reason) { return 2; }
#define get_hal_device_callbacks hwr_wmx_get_hal_device_callbacks
#define wifi_hal_ap_max_client_rejection_callback_register hwr_sg_wifi_hal_ap_max_client_rejection_callback_register

extern "C" {
wifi_device_callbacks_t *get_hal_device_callbacks()
{
    hwr_wmx_world.accessor_calls++;
    return hwr_wmx_world.no_cbs ? NULL : &hwr_wmx_world.cbs;
}

/* --- wifi_hal.c:4487-4498 --- */
void wifi_hal_ap_max_client_rejection_callback_register(wifi_apMaxClientRejection_callback func)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();

    if (callbacks == NULL) {
        return;
    }

    callbacks->max_cli_rejection_cb = func;
}
}
