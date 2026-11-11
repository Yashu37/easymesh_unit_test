/*
 * HANDLER: wifi_hal_apDeAuthEvent_callback_register (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:4446-4458 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It appends the callback to
 * callbacks->apDeAuthEvent_cb[num_apDeAuthEvent_cbs] and increments num_apDeAuthEvent_cbs, unless the callbacks table is not available or num_apDeAuthEvent_cbs >= MAX_REGISTERED_CB_NUM (4), in which case
 * it returns silently.
 *
 * Scaffolding only: get_hal_device_callbacks is an accessor over the runner's stand-alone table (the real one, wifi_hal.c:4764, returns the address of g_wifi_hal.callbacks); MAX_REGISTERED_CB_NUM is 4
 * (action_framework.h:59); renamed hwr_sg_wifi_hal_apDeAuthEvent_callback_register.
 */
#include "hwr_wde.h"
#include <stdio.h>
#include <string.h>

wifi_device_callbacks_t hwr_wde_table;
int hwr_wde_no_table;
INT hwr_wde_cb_a(int ap_index, char *src_mac, char *dest_mac, int frame_type, int reason) { return 1; }
INT hwr_wde_cb_b(int ap_index, char *src_mac, char *dest_mac, int frame_type, int reason) { return 2; }
#define get_hal_device_callbacks hwr_wde_get_hal_device_callbacks
#define wifi_hal_apDeAuthEvent_callback_register hwr_sg_wifi_hal_apDeAuthEvent_callback_register

extern "C" {
wifi_device_callbacks_t *get_hal_device_callbacks() { return hwr_wde_no_table ? NULL : &hwr_wde_table; }

/* --- wifi_hal.c:4446-4458 --- */
void wifi_hal_apDeAuthEvent_callback_register(wifi_device_deauthenticated_callback func)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();

    if (callbacks == NULL || callbacks->num_apDeAuthEvent_cbs >= MAX_REGISTERED_CB_NUM) {
        return;
    }

    callbacks->apDeAuthEvent_cb[callbacks->num_apDeAuthEvent_cbs] = func;
    callbacks->num_apDeAuthEvent_cbs++;
}
}
