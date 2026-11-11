/*
 * HANDLER: wifi_hal_eapol_timeouts_callback_register (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:4517-4529 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It appends the callback to
 * callbacks->eapol_timeouts_cb[num_eapol_timeouts_cbs] and increments num_eapol_timeouts_cbs, unless the callbacks table is not available or num_eapol_timeouts_cbs >= MAX_REGISTERED_CB_NUM (4),
 * in which case it returns silently.
 *
 * Scaffolding only: get_hal_device_callbacks is an accessor over the runner's stand-alone table (the real one, wifi_hal.c:4764, returns the address of g_wifi_hal.callbacks); MAX_REGISTERED_CB_NUM is 4
 * (action_framework.h:59); renamed hwr_sg_wifi_hal_eapol_timeouts_callback_register.
 */
#include "hwr_wet.h"
#include <stdio.h>
#include <string.h>

wifi_device_callbacks_t hwr_wet_table;
int hwr_wet_no_table;
INT hwr_wet_cb_a(int apIndex, char *mac, int type) { return 1; }
INT hwr_wet_cb_b(int apIndex, char *mac, int type) { return 2; }
#define get_hal_device_callbacks hwr_wet_get_hal_device_callbacks
#define wifi_hal_eapol_timeouts_callback_register hwr_sg_wifi_hal_eapol_timeouts_callback_register

extern "C" {
wifi_device_callbacks_t *get_hal_device_callbacks() { return hwr_wet_no_table ? NULL : &hwr_wet_table; }

/* --- wifi_hal.c:4517-4529 --- */
void wifi_hal_eapol_timeouts_callback_register(wifi_eapol_timeouts_callback func)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();
    
    if (callbacks == NULL || callbacks->num_eapol_timeouts_cbs >= MAX_REGISTERED_CB_NUM) {
        return;
    }
    
    callbacks->eapol_timeouts_cb[callbacks->num_eapol_timeouts_cbs] = func;
    callbacks->num_eapol_timeouts_cbs++;
}
}
