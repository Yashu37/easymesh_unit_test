/*
 * HANDLER: wifi_hal_BTMQueryRequest_callback_register (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:4728-4744 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It returns RETURN_ERR when apIndex >= MAX_AP_INDEX or the
 * callbacks table is not available; otherwise it stores both callbacks in callbacks->btm_callback[apIndex] (replacing any earlier ones, NULL included) and returns RETURN_OK.
 *
 * Scaffolding only: get_hal_device_callbacks is an accessor over the runner's stand-alone table (the real one, wifi_hal.c:4764, returns the address of g_wifi_hal.callbacks); MAX_AP_INDEX is 15
 * (action_framework.h:28); the callback stand-ins are plain functions cast to the real callback types; renamed hwr_sg_wifi_hal_BTMQueryRequest_callback_register.
 */
#include "hwr_wbq.h"
#include <stdio.h>
#include <string.h>

wifi_device_callbacks_t hwr_wbq_table;
int hwr_wbq_no_table, hwr_wbq_accessor_calls;
static void wbq_q_a(void) {} static void wbq_q_b(void) {} static void wbq_q_c(void) {}
static void wbq_r_a(void) {} static void wbq_r_b(void) {} static void wbq_r_c(void) {}
void *hwr_wbq_q(int k) { return k == 1 ? (void *)wbq_q_a : k == 2 ? (void *)wbq_q_b : k == 3 ? (void *)wbq_q_c : NULL; }
void *hwr_wbq_r(int k) { return k == 1 ? (void *)wbq_r_a : k == 2 ? (void *)wbq_r_b : k == 3 ? (void *)wbq_r_c : NULL; }
#define get_hal_device_callbacks hwr_wbq_get_hal_device_callbacks
#define wifi_hal_BTMQueryRequest_callback_register hwr_sg_wifi_hal_BTMQueryRequest_callback_register

extern "C" {
wifi_device_callbacks_t *get_hal_device_callbacks()
{
    hwr_wbq_accessor_calls++;
    return hwr_wbq_no_table ? NULL : &hwr_wbq_table;
}

/* --- wifi_hal.c:4728-4744 --- */
INT wifi_hal_BTMQueryRequest_callback_register(UINT apIndex,
                                            wifi_BTMQueryRequest_callback btmQueryCallback,
                                            wifi_BTMResponse_callback btmResponseCallback)
{
    wifi_device_callbacks_t *callbacks;

    if (apIndex >= MAX_AP_INDEX)
        return RETURN_ERR;

    callbacks = get_hal_device_callbacks();
    if (callbacks == NULL)
        return RETURN_ERR;

    callbacks->btm_callback[apIndex].query_callback = btmQueryCallback;
    callbacks->btm_callback[apIndex].response_callback = btmResponseCallback;
    return RETURN_OK;
}
}
