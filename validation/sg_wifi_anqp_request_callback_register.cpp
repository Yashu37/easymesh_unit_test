/*
 * HANDLER: wifi_anqp_request_callback_register (src/wifi_hal_anqp.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal_anqp.c:380-402 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It rejects a NULL callback (RETURN_ERR, debug print, accessor not used), otherwise it stores the callback in the ANQP request slot of
 * the device callbacks (replacing any earlier one); it returns RETURN_OK, or RETURN_ERR when the callbacks table is not available.
 *
 * Scaffolding only: get_device_callbacks is an accessor over the runner's world (the real one, wifi_hal_rdk_framework.h (get_device_callbacks), returns the address of g_wifi_hal.callbacks); renamed
 * hwr_sg_wifi_anqp_request_callback_register.
 */
#include "hwr_wqc.h"
#include <stdio.h>
#include <string.h>

hwr_wqc_world_t hwr_wqc_world;
void hwr_wqc_cb_a(UINT apIndex, mac_address_t sta, unsigned char token, wifi_anqp_node_t *list) { }
void hwr_wqc_cb_b(UINT apIndex, mac_address_t sta, unsigned char token, wifi_anqp_node_t *list) { }
#define wifi_anqp_dbg_print hwr_wqc_dbg
static void hwr_wqc_dbg(int level, const char *format, ...) { hwr_wqc_world.dbg_calls++; }
#define get_device_callbacks hwr_wqc_get_device_callbacks
#define wifi_anqp_request_callback_register hwr_sg_wifi_anqp_request_callback_register

extern "C" {
wifi_device_callbacks_t *get_device_callbacks()
{
    hwr_wqc_world.accessor_calls++;
    return hwr_wqc_world.no_cbs ? NULL : &hwr_wqc_world.cbs;
}

/* --- wifi_hal_anqp.c:380-402 --- */
INT wifi_anqp_request_callback_register(wifi_anqp_request_callback_t anqpReqCallback)
{
    wifi_device_callbacks_t *callbacks;

    if (!anqpReqCallback)
    {
        wifi_anqp_dbg_print(1, "%s:%d: received NULL callback function\n", __func__,__LINE__);
        return RETURN_ERR;
    }

    callbacks = get_device_callbacks();

    if (callbacks)
    {
        wifi_anqp_dbg_print(1, "%s:%d: setting anqp_req_callback \n", __func__,__LINE__);
        callbacks->anqp_req_callback = anqpReqCallback;
        return RETURN_OK;
    }
    else{
        wifi_anqp_dbg_print(1, "%s:%d: get_device_callbacks returned NULL \n", __func__,__LINE__);
        return RETURN_ERR;
    }
}
}
