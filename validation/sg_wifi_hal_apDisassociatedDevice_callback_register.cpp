/*
 * HANDLER: wifi_hal_apDisassociatedDevice_callback_register (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:4500-4512 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It appends the callback to
 * callbacks->disassoc_cb[num_disassoc_cbs] and increments num_disassoc_cbs, unless the callbacks table is not available or num_disassoc_cbs >= MAX_REGISTERED_CB_NUM (4),
 * in which case it returns silently.
 *
 * Scaffolding only: get_hal_device_callbacks is an accessor over the runner's stand-alone table (the real one, wifi_hal.c:4764, returns the address of g_wifi_hal.callbacks); MAX_REGISTERED_CB_NUM is 4
 * (action_framework.h:59); renamed hwr_sg_wifi_hal_apDisassociatedDevice_callback_register.
 */
#include "hwr_wdx.h"
#include <stdio.h>
#include <string.h>

wifi_device_callbacks_t hwr_wdx_table;
int hwr_wdx_no_table;
INT hwr_wdx_cb_a(INT apIndex, char *src_mac, char *dest_mac, INT frame_type, INT event_type) { return 1; }
INT hwr_wdx_cb_b(INT apIndex, char *src_mac, char *dest_mac, INT frame_type, INT event_type) { return 2; }
#define get_hal_device_callbacks hwr_wdx_get_hal_device_callbacks
#define wifi_hal_apDisassociatedDevice_callback_register hwr_sg_wifi_hal_apDisassociatedDevice_callback_register

extern "C" {
wifi_device_callbacks_t *get_hal_device_callbacks() { return hwr_wdx_no_table ? NULL : &hwr_wdx_table; }

/* --- wifi_hal.c:4500-4512 --- */
void wifi_hal_apDisassociatedDevice_callback_register(wifi_device_disassociated_callback func)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();

    if (callbacks == NULL || callbacks->num_disassoc_cbs >= MAX_REGISTERED_CB_NUM) {
        return;
    }

    callbacks->disassoc_cb[callbacks->num_disassoc_cbs] = func;
    callbacks->num_disassoc_cbs++;
}
}
