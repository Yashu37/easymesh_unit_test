/*
 * HANDLER: wifi_hal_radiusFallback_failover_callback_register (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:4600-4612 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It appends the callback to
 * callbacks->radius_failover_fallback_cbs[num_radius_fallback_failover_cbs] and increments num_radius_fallback_failover_cbs, unless the callbacks table is not available or num_radius_fallback_failover_cbs >= MAX_REGISTERED_CB_NUM (4),
 * in which case it returns silently.
 *
 * Scaffolding only: get_hal_device_callbacks is an accessor over the runner's stand-alone table (the real one, wifi_hal.c:4764, returns the address of g_wifi_hal.callbacks); MAX_REGISTERED_CB_NUM is 4
 * (action_framework.h:59); renamed hwr_sg_wifi_hal_radiusFallback_failover_callback_register.
 */
#include "hwr_wff.h"
#include <stdio.h>
#include <string.h>

wifi_device_callbacks_t hwr_wff_table;
int hwr_wff_no_table;
INT hwr_wff_cb_a(INT apIndex, INT failure_reason) { return 1; }
INT hwr_wff_cb_b(INT apIndex, INT failure_reason) { return 2; }
#define get_hal_device_callbacks hwr_wff_get_hal_device_callbacks
#define wifi_hal_radiusFallback_failover_callback_register hwr_sg_wifi_hal_radiusFallback_failover_callback_register

extern "C" {
wifi_device_callbacks_t *get_hal_device_callbacks() { return hwr_wff_no_table ? NULL : &hwr_wff_table; }

/* --- wifi_hal.c:4600-4612 --- */
void wifi_hal_radiusFallback_failover_callback_register(wifi_radiusFallback_failover_callback func)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();

    if (callbacks == NULL || callbacks->num_radius_fallback_failover_cbs >= MAX_REGISTERED_CB_NUM) {
        return;
    }

    callbacks->radius_failover_fallback_cbs[callbacks->num_radius_fallback_failover_cbs] = func;
    callbacks->num_radius_fallback_failover_cbs++;
}
}
