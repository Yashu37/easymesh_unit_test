/*
 * HANDLER: wifi_hal_handshake_callback_register (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:4545-4557 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It appends the callback to
 * callbacks->handshake_cb[num_handshake_cbs] and increments num_handshake_cbs, unless the callbacks table is not available or num_handshake_cbs >= MAX_REGISTERED_CB_NUM (4),
 * in which case it returns silently.
 *
 * Scaffolding only: get_hal_device_callbacks is an accessor over the runner's stand-alone table (the real one, wifi_hal.c:4764, returns the address of g_wifi_hal.callbacks); MAX_REGISTERED_CB_NUM is 4
 * (action_framework.h:59); renamed hwr_sg_wifi_hal_handshake_callback_register.
 */
#include "hwr_whs.h"
#include <stdio.h>
#include <string.h>

wifi_device_callbacks_t hwr_whs_table;
int hwr_whs_no_table;
INT hwr_whs_cb_a(int apIndex, char *mac, int status) { return 1; }
INT hwr_whs_cb_b(int apIndex, char *mac, int status) { return 2; }
#define get_hal_device_callbacks hwr_whs_get_hal_device_callbacks
#define wifi_hal_handshake_callback_register hwr_sg_wifi_hal_handshake_callback_register

extern "C" {
wifi_device_callbacks_t *get_hal_device_callbacks() { return hwr_whs_no_table ? NULL : &hwr_whs_table; }

/* --- wifi_hal.c:4545-4557 --- */
void wifi_hal_handshake_callback_register(wifi_handshake_callback func)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();
    
    if (callbacks == NULL || callbacks->num_handshake_cbs >= MAX_REGISTERED_CB_NUM) {
        return;
    }
    
    callbacks->handshake_cb[callbacks->num_handshake_cbs] = func;
    callbacks->num_handshake_cbs++;
}
}
