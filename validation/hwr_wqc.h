/* hwr_wqc.h - plumbing for the sg_wifi_anqp_request_callback_register harness (src/wifi_hal_anqp.c).
 * wifi_device_callbacks_t is a minimal STAND-IN with the member the function writes (anqp_req_callback) between two neighbouring members; wifi_anqp_request_callback_t is the REAL type from the
 * HAL headers.  get_device_callbacks (wifi_hal_rdk_framework.h) is an accessor over runner data that can also return NULL; wifi_anqp_dbg_print is a counting stub. */
#ifndef HWR_WQC_H
#define HWR_WQC_H
#include "hwr_defs.h"
typedef struct {
	void *before[2];
	wifi_anqp_request_callback_t anqp_req_callback;
	void *after[2];
} wifi_device_callbacks_t;
typedef struct { wifi_device_callbacks_t cbs; int no_cbs, accessor_calls, dbg_calls; } hwr_wqc_world_t;
extern hwr_wqc_world_t hwr_wqc_world;
extern "C" INT hwr_sg_wifi_anqp_request_callback_register(wifi_anqp_request_callback_t func);
void hwr_wqc_cb_a(UINT apIndex, mac_address_t sta, unsigned char token, wifi_anqp_node_t *list);
void hwr_wqc_cb_b(UINT apIndex, mac_address_t sta, unsigned char token, wifi_anqp_node_t *list);
typedef struct {
	const char *test_name;
	int old_cb;                    /* callback registered before: 0 none, 1 callback A, 2 callback B */
	int new_cb;                    /* callback passed: 0 NULL, 1 A, 2 B */
	int no_cbs;                    /* get_device_callbacks() returns NULL */
	int calls;                     /* number of consecutive registrations (the second one passes the other callback) */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wqc_case_t;
extern hwr_wqc_case_t sg_wifi_anqp_request_callback_register_suite[];
extern "C" void run_all_tests_sg_wifi_anqp_request_callback_register(void);
#endif
