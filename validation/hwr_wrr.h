/* hwr_wrr.h - plumbing for the sg_wifi_hal_RMBeaconRequestCallbackRegister harness (src/wifi_hal.c).
 * wifi_device_callbacks_t is a minimal STAND-IN with the member the function uses, bcnrpt_callback[MAX_AP_INDEX], between neighbouring members (action_framework.h:102); MAX_AP_INDEX is 15 (the default, VAP_REINDEX off,
 * action_framework.h:28).  wifi_RMBeaconReport_callback is the REAL type from the HAL headers.  The table is a stand-alone global so ASan sees an access past bcnrpt_callback[].
 * get_hal_device_callbacks (wifi_hal.c:4764) is an accessor over it that can also return NULL. */
#ifndef HWR_WRR_H
#define HWR_WRR_H
#include "hwr_defs.h"
#include <stdint.h>
#define MAX_AP_INDEX 15
#pragma pack(push, 8)
typedef struct {
	void *before[2];
	wifi_RMBeaconReport_callback bcnrpt_callback[MAX_AP_INDEX];
	void *after[2];
} wifi_device_callbacks_t;
#pragma pack(pop)
extern wifi_device_callbacks_t hwr_wrr_table;
extern int hwr_wrr_no_table, hwr_wrr_accessor_calls;
extern "C" INT hwr_sg_wifi_hal_RMBeaconRequestCallbackRegister(UINT apIndex, wifi_RMBeaconReport_callback beaconReportCallback);
INT hwr_wrr_cb_a(UINT apIndex, wifi_BeaconReport_t *out_struct, UINT *out_array_size, UCHAR *out_DialogToken);
INT hwr_wrr_cb_b(UINT apIndex, wifi_BeaconReport_t *out_struct, UINT *out_array_size, UCHAR *out_DialogToken);
INT hwr_wrr_cb_c(UINT apIndex, wifi_BeaconReport_t *out_struct, UINT *out_array_size, UCHAR *out_DialogToken);
typedef struct {
	const char *test_name;
	unsigned ap_index;             /* apIndex argument */
	int registered;                /* callback registered at ap_index: 0 none, 1 A, 2 B */
	int passed;                    /* callback passed: 0 NULL, 1 A, 2 B */
	int no_table;                  /* get_hal_device_callbacks() returns NULL */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wrr_case_t;
extern hwr_wrr_case_t sg_wifi_hal_RMBeaconRequestCallbackRegister_suite[];
extern "C" void run_all_tests_sg_wifi_hal_RMBeaconRequestCallbackRegister(void);
#endif
