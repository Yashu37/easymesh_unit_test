/* hwr_wmc.h - plumbing for the sg_wifi_hal_mgmt_frame_callbacks_register harness (src/wifi_hal.c).
 * wifi_device_callbacks_t is a minimal STAND-IN with the member the function writes (mgmt_frame_rx_callback) between two neighbouring members; wifi_receivedMgmtFrame_callback is the REAL type from the
 * HAL headers.  get_hal_device_callbacks (wifi_hal.c:4764) is an accessor over runner data that can also return NULL. */
#ifndef HWR_WMC_H
#define HWR_WMC_H
#include "hwr_defs.h"
typedef struct {
	void *before[2];
	wifi_receivedMgmtFrame_callback mgmt_frame_rx_callback;
	void *after[2];
} wifi_device_callbacks_t;
typedef struct { wifi_device_callbacks_t cbs; int no_cbs, accessor_calls; } hwr_wmc_world_t;
extern hwr_wmc_world_t hwr_wmc_world;
extern "C" int hwr_sg_wifi_hal_mgmt_frame_callbacks_register(wifi_receivedMgmtFrame_callback func);
int hwr_wmc_cb_a(INT ap_index, mac_address_t sta_mac, UCHAR *frame, UINT len, wifi_mgmtFrameType_t type, wifi_direction_t dir);
int hwr_wmc_cb_b(INT ap_index, mac_address_t sta_mac, UCHAR *frame, UINT len, wifi_mgmtFrameType_t type, wifi_direction_t dir);
typedef struct {
	const char *test_name;
	int old_cb;                    /* callback registered before: 0 none, 1 callback A, 2 callback B */
	int new_cb;                    /* callback passed: 0 NULL, 1 A, 2 B */
	int no_cbs;                    /* get_hal_device_callbacks() returns NULL */
	int calls;                     /* number of consecutive registrations (the second one passes the other callback) */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wmc_case_t;
extern hwr_wmc_case_t sg_wifi_hal_mgmt_frame_callbacks_register_suite[];
extern "C" void run_all_tests_sg_wifi_hal_mgmt_frame_callbacks_register(void);
#endif
