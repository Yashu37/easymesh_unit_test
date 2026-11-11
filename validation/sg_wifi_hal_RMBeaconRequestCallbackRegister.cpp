/*
 * HANDLER: wifi_hal_RMBeaconRequestCallbackRegister (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:4746-4762 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It returns RETURN_ERR when apIndex >= MAX_AP_INDEX, when the
 * callbacks table is not available or when a callback is already registered for apIndex; otherwise it stores the callback in callbacks->bcnrpt_callback[apIndex] and returns RETURN_OK.
 *
 * Scaffolding only: get_hal_device_callbacks is an accessor over the runner's stand-alone table (the real one, wifi_hal.c:4764, returns the address of g_wifi_hal.callbacks); MAX_AP_INDEX is 15
 * (action_framework.h:28); renamed hwr_sg_wifi_hal_RMBeaconRequestCallbackRegister.
 */
#include "hwr_wrr.h"
#include <stdio.h>
#include <string.h>

wifi_device_callbacks_t hwr_wrr_table;
int hwr_wrr_no_table, hwr_wrr_accessor_calls;
INT hwr_wrr_cb_a(UINT apIndex, wifi_BeaconReport_t *out_struct, UINT *out_array_size, UCHAR *out_DialogToken) { return 1; }
INT hwr_wrr_cb_b(UINT apIndex, wifi_BeaconReport_t *out_struct, UINT *out_array_size, UCHAR *out_DialogToken) { return 2; }
INT hwr_wrr_cb_c(UINT apIndex, wifi_BeaconReport_t *out_struct, UINT *out_array_size, UCHAR *out_DialogToken) { return 3; }
#define get_hal_device_callbacks hwr_wrr_get_hal_device_callbacks
#define wifi_hal_RMBeaconRequestCallbackRegister hwr_sg_wifi_hal_RMBeaconRequestCallbackRegister

extern "C" {
wifi_device_callbacks_t *get_hal_device_callbacks()
{
    hwr_wrr_accessor_calls++;
    return hwr_wrr_no_table ? NULL : &hwr_wrr_table;
}

/* --- wifi_hal.c:4746-4762 --- */
INT wifi_hal_RMBeaconRequestCallbackRegister(UINT apIndex, wifi_RMBeaconReport_callback beaconReportCallback)
{
    wifi_device_callbacks_t *callbacks;

    if (apIndex >= MAX_AP_INDEX)
        return RETURN_ERR;

    callbacks = get_hal_device_callbacks();
    if (callbacks == NULL)
        return RETURN_ERR;

    if (NULL != callbacks->bcnrpt_callback[apIndex])
        return RETURN_ERR;

    callbacks->bcnrpt_callback[apIndex] = beaconReportCallback;
    return RETURN_OK;
}
}
