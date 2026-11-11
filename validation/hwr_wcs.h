/* hwr_wcs.h - plumbing for the sg_wifi_hal_staConnectionStatus_callback_register harness (src/wifi_hal.c).
 * wifi_device_callbacks_t is a minimal STAND-IN with the member the function writes (sta_conn_status_callback) between two neighbouring members; wifi_staConnectionStatus_callback is the REAL type from the
 * HAL headers.  get_hal_device_callbacks (wifi_hal.c:4764) is an accessor over runner data that can also return NULL. */
#ifndef HWR_WCS_H
#define HWR_WCS_H
#include "hwr_defs.h"
typedef struct {
	void *before[2];
	wifi_staConnectionStatus_callback sta_conn_status_callback;
	void *after[2];
} wifi_device_callbacks_t;
typedef struct { wifi_device_callbacks_t cbs; int no_cbs, accessor_calls; } hwr_wcs_world_t;
extern hwr_wcs_world_t hwr_wcs_world;
extern "C" void hwr_sg_wifi_hal_staConnectionStatus_callback_register(wifi_staConnectionStatus_callback func);
INT hwr_wcs_cb_a(INT apIndex, wifi_bss_info_t *bss_dev, wifi_station_stats_t *sta);
INT hwr_wcs_cb_b(INT apIndex, wifi_bss_info_t *bss_dev, wifi_station_stats_t *sta);
typedef struct {
	const char *test_name;
	int old_cb;                    /* callback registered before: 0 none, 1 callback A, 2 callback B */
	int new_cb;                    /* callback passed: 0 NULL, 1 A, 2 B */
	int no_cbs;                    /* get_hal_device_callbacks() returns NULL */
	int calls;                     /* number of consecutive registrations (the second one passes the other callback) */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wcs_case_t;
extern hwr_wcs_case_t sg_wifi_hal_staConnectionStatus_callback_register_suite[];
extern "C" void run_all_tests_sg_wifi_hal_staConnectionStatus_callback_register(void);
#endif
