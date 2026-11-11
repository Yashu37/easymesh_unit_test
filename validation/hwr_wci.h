/* hwr_wci.h - plumbing for the sg_wifi_csi_callback_register harness (src/wifi_hal.c).
 * wifi_device_callbacks_t is a minimal STAND-IN with the member the function writes (csi_callback) between two neighbouring members; wifi_csi_callback is the REAL type from the
 * HAL headers.  get_hal_device_callbacks (wifi_hal.c:4764) is an accessor over runner data that can also return NULL. */
#ifndef HWR_WCI_H
#define HWR_WCI_H
#include "hwr_defs.h"
typedef struct {
	void *before[2];
	wifi_csi_callback csi_callback;
	void *after[2];
} wifi_device_callbacks_t;
typedef struct { wifi_device_callbacks_t cbs; int no_cbs, accessor_calls; } hwr_wci_world_t;
extern hwr_wci_world_t hwr_wci_world;
extern "C" void hwr_sg_wifi_csi_callback_register(wifi_csi_callback func);
INT hwr_wci_cb_a(mac_address_t mac_addr, wifi_csi_data_t *csi_data);
INT hwr_wci_cb_b(mac_address_t mac_addr, wifi_csi_data_t *csi_data);
typedef struct {
	const char *test_name;
	int old_cb;                    /* callback registered before: 0 none, 1 callback A, 2 callback B */
	int new_cb;                    /* callback passed: 0 NULL, 1 A, 2 B */
	int no_cbs;                    /* get_hal_device_callbacks() returns NULL */
	int calls;                     /* number of consecutive registrations (the second one passes the other callback) */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wci_case_t;
extern hwr_wci_case_t sg_wifi_csi_callback_register_suite[];
extern "C" void run_all_tests_sg_wifi_csi_callback_register(void);
#endif
