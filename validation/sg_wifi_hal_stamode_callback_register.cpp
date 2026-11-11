/*
 * HANDLER: wifi_hal_stamode_callback_register (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:4559-4571 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It appends the callback to
 * callbacks->stamode_cb[num_stamode_cbs] and increments num_stamode_cbs, unless the callbacks table is not available or num_stamode_cbs >= MAX_REGISTERED_CB_NUM (4),
 * in which case it returns silently.
 *
 * Scaffolding only: get_hal_device_callbacks is an accessor over the runner's stand-alone table (the real one, wifi_hal.c:4764, returns the address of g_wifi_hal.callbacks); MAX_REGISTERED_CB_NUM is 4
 * (action_framework.h:59); renamed hwr_sg_wifi_hal_stamode_callback_register.
 */
#include "hwr_wsm.h"
#include <stdio.h>
#include <string.h>

wifi_device_callbacks_t hwr_wsm_table;
int hwr_wsm_no_table;
INT hwr_wsm_cb_a(int apIndex, char *mac, int key_mgmt, int type, int radio, int mode) { return 1; }
INT hwr_wsm_cb_b(int apIndex, char *mac, int key_mgmt, int type, int radio, int mode) { return 2; }
#define get_hal_device_callbacks hwr_wsm_get_hal_device_callbacks
#define wifi_hal_stamode_callback_register hwr_sg_wifi_hal_stamode_callback_register

extern "C" {
wifi_device_callbacks_t *get_hal_device_callbacks() { return hwr_wsm_no_table ? NULL : &hwr_wsm_table; }

/* --- wifi_hal.c:4559-4571 --- */
void wifi_hal_stamode_callback_register(wifi_stamode_callback func)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();

    if (callbacks == NULL || callbacks->num_stamode_cbs >= MAX_REGISTERED_CB_NUM) {
        return;
    }

    callbacks->stamode_cb[callbacks->num_stamode_cbs] = func;
    callbacks->num_stamode_cbs++;
}
}
