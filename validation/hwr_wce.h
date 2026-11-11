/* hwr_wce.h - plumbing for the sg_wifi_chan_event_register harness (src/wifi_hal.c).
 * wifi_device_callbacks_t is a minimal STAND-IN with the member the function writes (channel_change_event_callback) between two neighbouring members; wifi_chan_event_CB_t is the REAL type from the
 * HAL headers.  get_hal_device_callbacks (wifi_hal.c:4764) is an accessor over runner data that can also return NULL. */
#ifndef HWR_WCE_H
#define HWR_WCE_H
#include "hwr_defs.h"
/* STAND-IN copied from src/wifi_hal_rdk_framework.h:106-115 (that header pulls in the whole framework); its member types are the REAL ones from the HAL headers. */
typedef struct {
	wifi_radio_index_t radioIndex;
	wifi_chan_eventType_t event;
	wifi_radar_eventType_t sub_event;
	UINT channel;
	wifi_channelBandwidth_t channelWidth;
	UINT op_class;
} __attribute__((__packed__)) wifi_channel_change_event_t;
typedef void (*wifi_chan_event_CB_t)(wifi_channel_change_event_t radio_channel_param);
typedef struct {
	void *before[2];
	wifi_chan_event_CB_t channel_change_event_callback;
	void *after[2];
} wifi_device_callbacks_t;
typedef struct { wifi_device_callbacks_t cbs; int no_cbs, accessor_calls; } hwr_wce_world_t;
extern hwr_wce_world_t hwr_wce_world;
extern "C" INT hwr_sg_wifi_chan_event_register(wifi_chan_event_CB_t func);
void hwr_wce_cb_a(wifi_channel_change_event_t radio_channel_param);
void hwr_wce_cb_b(wifi_channel_change_event_t radio_channel_param);
typedef struct {
	const char *test_name;
	int old_cb;                    /* callback registered before: 0 none, 1 callback A, 2 callback B */
	int new_cb;                    /* callback passed: 0 NULL, 1 A, 2 B */
	int no_cbs;                    /* get_hal_device_callbacks() returns NULL */
	int calls;                     /* number of consecutive registrations (the second one passes the other callback) */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wce_case_t;
extern hwr_wce_case_t sg_wifi_chan_event_register_suite[];
extern "C" void run_all_tests_sg_wifi_chan_event_register(void);
#endif
