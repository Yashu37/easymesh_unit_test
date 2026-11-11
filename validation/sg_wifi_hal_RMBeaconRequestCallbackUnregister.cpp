/*
 * HANDLER: wifi_hal_RMBeaconRequestCallbackUnregister (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:4710-4726 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It returns RETURN_ERR when apIndex >= MAX_AP_INDEX, when the
 * callbacks table is not available or when the callback passed differs from the one registered for apIndex; otherwise it clears callbacks->bcnrpt_callback[apIndex] and returns RETURN_OK.
 *
 * Scaffolding only: get_hal_device_callbacks is an accessor over the runner's stand-alone table (the real one, wifi_hal.c:4764, returns the address of g_wifi_hal.callbacks); MAX_AP_INDEX is 15
 * (action_framework.h:28); renamed hwr_sg_wifi_hal_RMBeaconRequestCallbackUnregister.
 */
#include "hwr_wru.h"
#include <stdio.h>
#include <string.h>

wifi_device_callbacks_t hwr_wru_table;
int hwr_wru_no_table, hwr_wru_accessor_calls;
INT hwr_wru_cb_a(UINT apIndex, wifi_BeaconReport_t *out_struct, UINT *out_array_size, UCHAR *out_DialogToken) { return 1; }
INT hwr_wru_cb_b(UINT apIndex, wifi_BeaconReport_t *out_struct, UINT *out_array_size, UCHAR *out_DialogToken) { return 2; }
INT hwr_wru_cb_c(UINT apIndex, wifi_BeaconReport_t *out_struct, UINT *out_array_size, UCHAR *out_DialogToken) { return 3; }
#define get_hal_device_callbacks hwr_wru_get_hal_device_callbacks
#define wifi_hal_RMBeaconRequestCallbackUnregister hwr_sg_wifi_hal_RMBeaconRequestCallbackUnregister

extern "C" {
wifi_device_callbacks_t *get_hal_device_callbacks()
{
    hwr_wru_accessor_calls++;
    return hwr_wru_no_table ? NULL : &hwr_wru_table;
}

/* --- wifi_hal.c:4710-4726 --- */
INT wifi_hal_RMBeaconRequestCallbackUnregister(UINT apIndex, wifi_RMBeaconReport_callback beaconReportCallback)
{
    wifi_device_callbacks_t *callbacks;

    if (apIndex >= MAX_AP_INDEX)
        return RETURN_ERR;

    callbacks = get_hal_device_callbacks();
    if (callbacks == NULL)
        return RETURN_ERR;

    if (beaconReportCallback != callbacks->bcnrpt_callback[apIndex])
        return RETURN_ERR;

    callbacks->bcnrpt_callback[apIndex] = NULL;
    return RETURN_OK;
}
}
