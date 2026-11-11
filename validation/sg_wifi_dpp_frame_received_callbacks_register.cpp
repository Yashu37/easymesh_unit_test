/*
 * HANDLER: wifi_dpp_frame_received_callbacks_register (src/wifi_hal_dpp.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal_dpp.c:2161-2178 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It stores the five DPP frame callbacks (auth response,
 * config request, config result, reconfig announce, reconfig auth response; NULL included, which clears a slot) in the device callbacks table returned by get_device_callbacks() and returns RETURN_OK.
 *
 * Scaffolding only: get_device_callbacks is an accessor over the runner's table (the real one, wifi_hal_rdk_util.c:68, returns &g_device_callbacks and never NULL); renamed
 * hwr_sg_wifi_dpp_frame_received_callbacks_register.
 */
#include "hwr_wdg.h"
#include <string.h>

#define RETURN_OK 0
#define RETURN_ERR -1
hwr_wdg_world_t hwr_wdg_world;
extern "C" void hwr_wdg_cb_a(void) { }
extern "C" void hwr_wdg_cb_b(void) { }
#define get_device_callbacks hwr_wdg_get_device_callbacks
#define wifi_dpp_frame_received_callbacks_register hwr_sg_wifi_dpp_frame_received_callbacks_register

extern "C" {
wifi_device_callbacks_t *get_device_callbacks()
{
    hwr_wdg_world.accessor_calls++;
    return &hwr_wdg_world.cbs;
}

/* --- wifi_hal_dpp.c:2161-2178 --- */
INT wifi_dpp_frame_received_callbacks_register(wifi_dppAuthResponse_callback_t dppAuthCallback,
                                    wifi_dppConfigRequest_callback_t dppConfigCallback,
                                    wifi_dppConfigResult_callback_t dppConfigResultCallback,
                                    wifi_dppReconfigAnnounce_callback_t dppReconfigAnnounceCallback,
                                    wifi_dppReconfigAuthResponse_callback_t dppReconfigAuthRspCallback)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_device_callbacks();

    callbacks->dpp_auth_rsp_callback = dppAuthCallback;
    callbacks->dpp_config_req_callback = dppConfigCallback;
	callbacks->dpp_config_result_callback = dppConfigResultCallback;
	callbacks->dpp_reconfig_announce_callback = dppReconfigAnnounceCallback;
	callbacks->dpp_reconfig_auth_rsp_callback = dppReconfigAuthRspCallback;

    return RETURN_OK;
}
}
