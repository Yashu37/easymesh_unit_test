/*
 * HANDLER: wifi_csi_callback_register (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:4683-4693 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes); the function exists only under #ifdef CMXB7_PORT (wifi_hal.c:4682-4694), the body is copied without the preprocessor lines.  It stores the callback in the CSI slot of
 * the HAL device callbacks (replacing any earlier one; NULL clears it); it returns void and does nothing when the callbacks table is not available.
 *
 * Scaffolding only: get_hal_device_callbacks is an accessor over the runner's world (the real one, wifi_hal.c:4764, returns the address of g_wifi_hal.callbacks); renamed
 * hwr_sg_wifi_csi_callback_register.
 */
#include "hwr_wci.h"
#include <stdio.h>
#include <string.h>

hwr_wci_world_t hwr_wci_world;
INT hwr_wci_cb_a(mac_address_t mac_addr, wifi_csi_data_t *csi_data) { return 1; }
INT hwr_wci_cb_b(mac_address_t mac_addr, wifi_csi_data_t *csi_data) { return 2; }
#define get_hal_device_callbacks hwr_wci_get_hal_device_callbacks
#define wifi_csi_callback_register hwr_sg_wifi_csi_callback_register

extern "C" {
wifi_device_callbacks_t *get_hal_device_callbacks()
{
    hwr_wci_world.accessor_calls++;
    return hwr_wci_world.no_cbs ? NULL : &hwr_wci_world.cbs;
}

/* --- wifi_hal.c:4683-4693 --- */
void wifi_csi_callback_register(wifi_csi_callback callback_proc)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();
    if (callbacks == NULL) {
        return;
    }

    callbacks->csi_callback = callback_proc;
}
}
