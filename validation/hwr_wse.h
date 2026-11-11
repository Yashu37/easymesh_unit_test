/* hwr_wse.h - plumbing for the sg_wifi_hal_steering_eventRegister harness (src/wifi_hal.c).
 * wifi_device_callbacks_t is a minimal STAND-IN with the member the function writes (steering_event_callback) between two neighbouring members; wifi_steering_eventCB_t is the REAL type from the
 * HAL headers.  get_hal_device_callbacks (wifi_hal.c:4764) is an accessor over runner data that can also return NULL. */
#ifndef HWR_WSE_H
#define HWR_WSE_H
#include "hwr_defs.h"
typedef struct {
	void *before[2];
	wifi_steering_eventCB_t steering_event_callback;
	void *after[2];
} wifi_device_callbacks_t;
typedef struct { wifi_device_callbacks_t cbs; int no_cbs, accessor_calls, steer_calls; void *steer_arg; } hwr_wse_world_t;
extern hwr_wse_world_t hwr_wse_world;
extern "C" void nl80211_steering_event(UINT steeringgroupIndex, wifi_steering_event_t *event);
extern "C" INT hwr_sg_wifi_hal_steering_eventRegister(wifi_steering_eventCB_t func);
void hwr_wse_cb_a(UINT steeringgroupIndex, wifi_steering_event_t *event);
void hwr_wse_cb_b(UINT steeringgroupIndex, wifi_steering_event_t *event);
typedef struct {
	const char *test_name;
	int old_cb;                    /* callback registered before: 0 none, 1 callback A, 2 callback B */
	int new_cb;                    /* callback passed: 0 NULL, 1 A, 2 B */
	int no_cbs;                    /* get_hal_device_callbacks() returns NULL */
	int calls;                     /* number of consecutive registrations (the second one passes the other callback) */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wse_case_t;
extern hwr_wse_case_t sg_wifi_hal_steering_eventRegister_suite[];
extern "C" void run_all_tests_sg_wifi_hal_steering_eventRegister(void);
#endif
