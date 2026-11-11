/* hwr_wdg.h - plumbing for the sg_wifi_dpp_frame_received_callbacks_register harness (src/wifi_hal_dpp.c).
 * wifi_device_callbacks_t is a minimal STAND-IN with the five DPP callback members the function writes (dpp_auth_rsp_callback, dpp_config_req_callback, dpp_config_result_callback,
 * dpp_reconfig_announce_callback, dpp_reconfig_auth_rsp_callback) between neighbouring members; the callback types are the REAL HAL types.  get_device_callbacks (wifi_hal_rdk_util.c:68) returns the
 * address of a global table and never NULL, so the accessor here does the same over runner data. */
#ifndef HWR_WDG_H
#define HWR_WDG_H
#include "hwr_defs.h"
typedef struct {
	void *before[2];
	wifi_dppAuthResponse_callback_t dpp_auth_rsp_callback;
	wifi_dppConfigRequest_callback_t dpp_config_req_callback;
	wifi_dppConfigResult_callback_t dpp_config_result_callback;
	wifi_dppReconfigAnnounce_callback_t dpp_reconfig_announce_callback;
	wifi_dppReconfigAuthResponse_callback_t dpp_reconfig_auth_rsp_callback;
	void *after[2];
} wifi_device_callbacks_t;
typedef struct { wifi_device_callbacks_t cbs; int accessor_calls; } hwr_wdg_world_t;
extern hwr_wdg_world_t hwr_wdg_world;
extern "C" INT hwr_sg_wifi_dpp_frame_received_callbacks_register(wifi_dppAuthResponse_callback_t a, wifi_dppConfigRequest_callback_t b, wifi_dppConfigResult_callback_t c, wifi_dppReconfigAnnounce_callback_t d, wifi_dppReconfigAuthResponse_callback_t e);
extern "C" void hwr_wdg_cb_a(void);
extern "C" void hwr_wdg_cb_b(void);
typedef struct {
	const char *test_name;
	int old[5];                    /* callback held per slot before: 0 none, 1 callback A, 2 callback B */
	int arg[5];                    /* callback passed per slot: 0 NULL, 1 A, 2 B */
	int calls;                     /* 1 or 2 consecutive registrations (the second one passes the swapped callbacks) */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wdg_case_t;
extern hwr_wdg_case_t sg_wifi_dpp_frame_received_callbacks_register_suite[];
extern "C" void run_all_tests_sg_wifi_dpp_frame_received_callbacks_register(void);
#endif
