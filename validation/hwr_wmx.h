/* hwr_wmx.h - plumbing for the sg_wifi_hal_ap_max_client_rejection_callback_register harness (src/wifi_hal.c).
 * wifi_device_callbacks_t is a minimal STAND-IN with the member the function writes (max_cli_rejection_cb) between two neighbouring members; wifi_apMaxClientRejection_callback is the REAL type from the
 * HAL headers.  get_hal_device_callbacks (wifi_hal.c:4764) is an accessor over runner data that can also return NULL. */
#ifndef HWR_WMX_H
#define HWR_WMX_H
#include "hwr_defs.h"
typedef struct {
	void *before[2];
	wifi_apMaxClientRejection_callback max_cli_rejection_cb;
	void *after[2];
} wifi_device_callbacks_t;
typedef struct { wifi_device_callbacks_t cbs; int no_cbs, accessor_calls; } hwr_wmx_world_t;
extern hwr_wmx_world_t hwr_wmx_world;
extern "C" void hwr_sg_wifi_hal_ap_max_client_rejection_callback_register(wifi_apMaxClientRejection_callback func);
INT hwr_wmx_cb_a(INT apIndex, char *MAC, INT reason);
INT hwr_wmx_cb_b(INT apIndex, char *MAC, INT reason);
typedef struct {
	const char *test_name;
	int old_cb;                    /* callback registered before: 0 none, 1 callback A, 2 callback B */
	int new_cb;                    /* callback passed: 0 NULL, 1 A, 2 B */
	int no_cbs;                    /* get_hal_device_callbacks() returns NULL */
	int calls;                     /* number of consecutive registrations (the second one passes the other callback) */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wmx_case_t;
extern hwr_wmx_case_t sg_wifi_hal_ap_max_client_rejection_callback_register_suite[];
extern "C" void run_all_tests_sg_wifi_hal_ap_max_client_rejection_callback_register(void);
#endif
