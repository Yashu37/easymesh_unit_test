/*
 * HANDLER: wifi_hal_apStatusCode_callback_register (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:4573-4585 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It appends the callback to
 * callbacks->statuscode_cb[num_statuscode_cbs] and increments num_statuscode_cbs, unless the callbacks table is not available or num_statuscode_cbs >= MAX_REGISTERED_CB_NUM (4),
 * in which case it returns silently.
 *
 * Scaffolding only: get_hal_device_callbacks is an accessor over the runner's stand-alone table (the real one, wifi_hal.c:4764, returns the address of g_wifi_hal.callbacks); MAX_REGISTERED_CB_NUM is 4
 * (action_framework.h:59); renamed hwr_sg_wifi_hal_apStatusCode_callback_register.
 */
#include "hwr_wsa.h"
#include <stdio.h>
#include <string.h>

wifi_device_callbacks_t hwr_wsa_table;
int hwr_wsa_no_table;
INT hwr_wsa_cb_a(int apIndex, char *src_mac, char *dest_mac, int frame_type, int status) { return 1; }
INT hwr_wsa_cb_b(int apIndex, char *src_mac, char *dest_mac, int frame_type, int status) { return 2; }
#define get_hal_device_callbacks hwr_wsa_get_hal_device_callbacks
#define wifi_hal_apStatusCode_callback_register hwr_sg_wifi_hal_apStatusCode_callback_register

extern "C" {
wifi_device_callbacks_t *get_hal_device_callbacks() { return hwr_wsa_no_table ? NULL : &hwr_wsa_table; }

/* --- wifi_hal.c:4573-4585 --- */
void wifi_hal_apStatusCode_callback_register(wifi_apStatusCode_callback func)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();

    if (callbacks == NULL || callbacks->num_statuscode_cbs >= MAX_REGISTERED_CB_NUM) {
        return;
    }

    callbacks->statuscode_cb[callbacks->num_statuscode_cbs] = func;
    callbacks->num_statuscode_cbs++;
}
}
