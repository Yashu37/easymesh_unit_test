/*
 * HANDLER: wifi_vapstatus_callback_register (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:4474-4485 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It appends the callback to
 * callbacks->vapstatus_cb[num_vapstatus_cbs] and increments num_vapstatus_cbs, unless the callbacks table is not available or num_vapstatus_cbs >= MAX_REGISTERED_CB_NUM (4),
 * in which case it returns RETURN_ERR (RETURN_OK after storing).
 *
 * Scaffolding only: get_hal_device_callbacks is an accessor over the runner's stand-alone table (the real one, wifi_hal.c:4764, returns the address of g_wifi_hal.callbacks); MAX_REGISTERED_CB_NUM is 4
 * (action_framework.h:59); renamed hwr_sg_wifi_vapstatus_callback_register.
 */
#include "hwr_wvs.h"
#include <stdio.h>
#include <string.h>

wifi_device_callbacks_t hwr_wvs_table;
int hwr_wvs_no_table;
INT hwr_wvs_cb_a(INT apIndex, wifi_vapstatus_t status) { return 1; }
INT hwr_wvs_cb_b(INT apIndex, wifi_vapstatus_t status) { return 2; }
#define get_hal_device_callbacks hwr_wvs_get_hal_device_callbacks
#define wifi_vapstatus_callback_register hwr_sg_wifi_vapstatus_callback_register

extern "C" {
wifi_device_callbacks_t *get_hal_device_callbacks() { return hwr_wvs_no_table ? NULL : &hwr_wvs_table; }

/* --- wifi_hal.c:4474-4485 --- */
INT wifi_vapstatus_callback_register(wifi_vapstatus_callback func) {
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();

    if (callbacks == NULL || callbacks->num_vapstatus_cbs >= MAX_REGISTERED_CB_NUM) {
        return RETURN_ERR;
    }
    callbacks->vapstatus_cb[callbacks->num_vapstatus_cbs] = func;
    callbacks->num_vapstatus_cbs++;
    return RETURN_OK;
}
}
