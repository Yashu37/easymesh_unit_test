/*
 * HANDLER: callback_dpp_config_req_frame_received (src/wifi_hal_dpp.c)
 *
 * Function copied (verbatim apart from fix 1: start fix 1 / end fix 1 markers; the unfixed copy is the reproducer) from rdk-wifi-hal: src/wifi_hal_dpp.c:2839-2845 (~/Desktop/G/rdk-wifi-hal).  This file holds the code WITH fix 1.  It forwards a received DPP Configuration Request
 * (ap index, station mac, token, attribute buffer and its length) to the dpp_config_req_callback registered in the device callbacks table returned by get_device_callbacks().
 *
 * Scaffolding only: get_device_callbacks is an accessor over the runner's table (the real one, wifi_hal_rdk_util.c:68, returns &g_device_callbacks and never NULL); the registered callback is a
 * recording mock; renamed hwr_sg_callback_dpp_config_req_frame_received.
 */
#include "hwr_wcf.h"
#include <string.h>

hwr_wcf_world_t hwr_wcf_world;
#define get_device_callbacks hwr_wcf_get_device_callbacks
#define callback_dpp_config_req_frame_received hwr_sg_callback_dpp_config_req_frame_received

extern "C" {
wifi_device_callbacks_t *get_device_callbacks()
{
    hwr_wcf_world.accessor_calls++;
    return &hwr_wcf_world.cbs;
}

/* --- wifi_hal_dpp.c:2839-2845 --- */
void callback_dpp_config_req_frame_received(int ap_index, mac_address_t sta, unsigned char token, unsigned char  *attrib, unsigned int len)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_device_callbacks();
    /* ---------- start fix 1: dpp_config_req_callback is NULL until wifi_dpp_frame_received_callbacks_register sets it (or after it clears it with NULL): the call went through a NULL pointer. */
    if ((callbacks == NULL) || (callbacks->dpp_config_req_callback == NULL)) {
        return;
    }
    /* ---------- end fix 1 */
    callbacks->dpp_config_req_callback(ap_index, sta, token, attrib, len);
}
}
