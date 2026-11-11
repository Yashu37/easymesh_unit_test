/*
 * HANDLER: wifi_hal_newApAssociatedDevice_callback_register (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:4432-4444 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It appends the callback to
 * callbacks->assoc_cb[num_assoc_cbs] and increments num_assoc_cbs, unless the callbacks table is not available or num_assoc_cbs >= MAX_REGISTERED_CB_NUM (4), in which case it returns silently.
 *
 * Scaffolding only: get_hal_device_callbacks is an accessor over the runner's stand-alone table (the real one, wifi_hal.c:4764, returns the address of g_wifi_hal.callbacks); MAX_REGISTERED_CB_NUM is 4
 * (action_framework.h:59); renamed hwr_sg_wifi_hal_newApAssociatedDevice_callback_register.
 */
#include "hwr_wna.h"
#include <stdio.h>
#include <string.h>

wifi_device_callbacks_t hwr_wna_table;
int hwr_wna_no_table;
INT hwr_wna_cb_a(INT ap_index, wifi_associated_dev_t *assoc_dev) { return 1; }
INT hwr_wna_cb_b(INT ap_index, wifi_associated_dev_t *assoc_dev) { return 2; }
#define get_hal_device_callbacks hwr_wna_get_hal_device_callbacks
#define wifi_hal_newApAssociatedDevice_callback_register hwr_sg_wifi_hal_newApAssociatedDevice_callback_register

extern "C" {
wifi_device_callbacks_t *get_hal_device_callbacks() { return hwr_wna_no_table ? NULL : &hwr_wna_table; }

/* --- wifi_hal.c:4432-4444 --- */
void wifi_hal_newApAssociatedDevice_callback_register(wifi_newApAssociatedDevice_callback func)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();

    if (callbacks == NULL || callbacks->num_assoc_cbs >= MAX_REGISTERED_CB_NUM) {
        return;
    }

    callbacks->assoc_cb[callbacks->num_assoc_cbs] = func;
    callbacks->num_assoc_cbs++;
}
}
