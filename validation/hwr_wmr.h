/* hwr_wmr.h - plumbing for the sg_wifi_hal_send_mgmt_frame_response harness (src/wifi_hal.c) */
#ifndef HWR_WMR_H
#define HWR_WMR_H
#include "hwr_defs.h"
#include <stdint.h>
typedef struct {
	int ok_calls, deny_calls;
	int ap; const uint8_t *frame; int len;                  /* last wifi_send_wpa_supplicant_event arguments */
	int fap; const uint8_t *mac; int type, status_code, rssi; /* last wifi_send_response_failure arguments */
} hwr_wmr_world_t;
extern hwr_wmr_world_t hwr_wmr_world;
extern "C" int hwr_sg_wifi_hal_send_mgmt_frame_response(int ap_index, int type, int status, int status_code, uint8_t *frame, uint8_t *mac, int len, int rssi);
typedef struct {
	const char *test_name;
	int status;                    /* 0 = MGMT_FRAME_RESPONSE_STATUS_OK, 1 = ..._DENY, anything else is undefined */
	int ap_index, type, status_code;
	int ptr_mode;                  /* frame and mac: 0 NULL, 1 pointers into fully POISONED runner slabs (the wrapper must not touch them), 2 dangling 0xdeadbeef / 0xcafef00d */
	int len, rssi;
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call */
	int expected_ret;
} hwr_wmr_case_t;
extern hwr_wmr_case_t sg_wifi_hal_send_mgmt_frame_response_suite[];
extern "C" void run_all_tests_sg_wifi_hal_send_mgmt_frame_response(void);
#endif
