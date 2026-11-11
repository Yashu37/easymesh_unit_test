/* hwr_wbq.h - plumbing for the sg_wifi_hal_BTMQueryRequest_callback_register harness (src/wifi_hal.c).
 * wifi_device_callbacks_t is a minimal STAND-IN with the member the function writes, btm_callback[MAX_AP_INDEX] (wifi_BTM_callbacks_t = query_callback + response_callback, action_framework.h:90-93,103), between
 * neighbouring members; MAX_AP_INDEX is 15 (the default, VAP_REINDEX off, action_framework.h:28).  wifi_BTMQueryRequest_callback / wifi_BTMResponse_callback are the REAL types from the HAL headers.  The table is
 * a stand-alone global so ASan sees a write past btm_callback[].  get_hal_device_callbacks (wifi_hal.c:4764) is an accessor over it that can also return NULL. */
#ifndef HWR_WBQ_H
#define HWR_WBQ_H
#include "hwr_defs.h"
#include <stdint.h>
#define MAX_AP_INDEX 15
typedef struct {
	wifi_BTMQueryRequest_callback query_callback;
	wifi_BTMResponse_callback response_callback;
} wifi_BTM_callbacks_t;
#pragma pack(push, 8)
typedef struct {
	void *before[2];
	wifi_BTM_callbacks_t btm_callback[MAX_AP_INDEX];
	void *after[2];
} wifi_device_callbacks_t;
#pragma pack(pop)
extern wifi_device_callbacks_t hwr_wbq_table;
extern int hwr_wbq_no_table, hwr_wbq_accessor_calls;
extern "C" INT hwr_sg_wifi_hal_BTMQueryRequest_callback_register(UINT apIndex, wifi_BTMQueryRequest_callback btmQueryCallback, wifi_BTMResponse_callback btmResponseCallback);
void *hwr_wbq_q(int k);           /* query callback stand-ins: 0 NULL, 1 A, 2 B, 3 C (other slots) */
void *hwr_wbq_r(int k);           /* response callback stand-ins */
typedef struct {
	const char *test_name;
	unsigned ap_index;             /* apIndex argument */
	int old_q, old_r;              /* callbacks registered at ap_index before: 0 none, 1 A, 2 B */
	int new_q, new_r;              /* callbacks passed: 0 NULL, 1 A, 2 B */
	int no_table;                  /* get_hal_device_callbacks() returns NULL */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wbq_case_t;
extern hwr_wbq_case_t sg_wifi_hal_BTMQueryRequest_callback_register_suite[];
extern "C" void run_all_tests_sg_wifi_hal_BTMQueryRequest_callback_register(void);
#endif
