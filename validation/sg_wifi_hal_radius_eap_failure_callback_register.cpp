/*
 * HANDLER: wifi_hal_radius_eap_failure_callback_register (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:4587-4598 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It appends the callback to
 * callbacks->radius_eap_cb[num_radius_eap_cbs] and increments num_radius_eap_cbs, unless the callbacks table is not available or num_radius_eap_cbs >= MAX_REGISTERED_CB_NUM (4),
 * in which case it returns silently.
 *
 * Scaffolding only: get_hal_device_callbacks is an accessor over the runner's stand-alone table (the real one, wifi_hal.c:4764, returns the address of g_wifi_hal.callbacks); MAX_REGISTERED_CB_NUM is 4
 * (action_framework.h:59); renamed hwr_sg_wifi_hal_radius_eap_failure_callback_register.
 */
#include "hwr_wre.h"
#include <stdio.h>
#include <string.h>

wifi_device_callbacks_t hwr_wre_table;
int hwr_wre_no_table;
INT hwr_wre_cb_a(INT apIndex, mac_address_t sta_mac, INT failure_reason) { return 1; }
INT hwr_wre_cb_b(INT apIndex, mac_address_t sta_mac, INT failure_reason) { return 2; }
#define get_hal_device_callbacks hwr_wre_get_hal_device_callbacks
#define wifi_hal_radius_eap_failure_callback_register hwr_sg_wifi_hal_radius_eap_failure_callback_register

extern "C" {
wifi_device_callbacks_t *get_hal_device_callbacks() { return hwr_wre_no_table ? NULL : &hwr_wre_table; }

/* --- wifi_hal.c:4587-4598 --- */
void wifi_hal_radius_eap_failure_callback_register(wifi_radiusEapFailure_callback func)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();

    if (callbacks == NULL || callbacks->num_radius_eap_cbs >= MAX_REGISTERED_CB_NUM) {
        return;
    }
    callbacks->radius_eap_cb[callbacks->num_radius_eap_cbs] = func;
    callbacks->num_radius_eap_cbs++;
}
}
