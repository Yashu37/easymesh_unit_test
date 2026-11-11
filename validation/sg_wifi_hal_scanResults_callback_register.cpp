/*
 * HANDLER: wifi_hal_scanResults_callback_register (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:4628-4640 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It stores the callback in the scan-results slot of
 * the HAL device callbacks (replacing any earlier one; NULL clears it); it returns void and does nothing when the callbacks table is not available.
 *
 * Scaffolding only: get_hal_device_callbacks is an accessor over the runner's world (the real one, wifi_hal.c:4764, returns the address of g_wifi_hal.callbacks); renamed
 * hwr_sg_wifi_hal_scanResults_callback_register.
 */
#include "hwr_wsq.h"
#include <stdio.h>
#include <string.h>

hwr_wsq_world_t hwr_wsq_world;
INT hwr_wsq_cb_a(wifi_radio_index_t index, wifi_bss_info_t **bss, UINT *num_bss) { return 1; }
INT hwr_wsq_cb_b(wifi_radio_index_t index, wifi_bss_info_t **bss, UINT *num_bss) { return 2; }
#define get_hal_device_callbacks hwr_wsq_get_hal_device_callbacks
#define wifi_hal_scanResults_callback_register hwr_sg_wifi_hal_scanResults_callback_register

extern "C" {
wifi_device_callbacks_t *get_hal_device_callbacks()
{
    hwr_wsq_world.accessor_calls++;
    return hwr_wsq_world.no_cbs ? NULL : &hwr_wsq_world.cbs;
}

/* --- wifi_hal.c:4628-4640 --- */
void wifi_hal_scanResults_callback_register(wifi_scanResults_callback func)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();
    if (callbacks == NULL) {
        return;
    }

    callbacks->scan_result_callback = func;

    return;
}
}
