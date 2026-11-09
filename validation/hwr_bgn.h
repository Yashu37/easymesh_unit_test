/* hwr_bgn.h - plumbing for the broadcom wifi_getNeighboringWiFiStatus harness (platform/broadcom) */
#ifndef HWR_BGN_H
#define HWR_BGN_H
#include "hwr_defs.h"
extern "C" INT hwr_bcm_wifi_getNeighboringWiFiStatus(INT radio_index, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *output_array_size);
typedef struct {
	int calls, last_radio;
	wifi_neighbor_ap2_t **last_array; UINT *last_size;
	int ret;                       /* what the stub wifi_hal_getNeighboringWiFiStatus returns */
} hwr_bgn_world_t;
extern hwr_bgn_world_t hwr_bgn_world;
typedef struct {
	const char *test_name;
	int radio_index;
	int array_mode;                /* 0 neighbor_ap_array NULL, 1 the runner's (poisoned) slot, 2 dangling 0xdeadbeef */
	int size_mode;                 /* same for output_array_size */
	int core_ret;                  /* return value of wifi_hal_getNeighboringWiFiStatus */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call */
} hwr_bgn_case_t;
extern hwr_bgn_case_t wifi_getNeighboringWiFiStatus_bcm_suite[];
extern "C" void run_all_tests_wifi_getNeighboringWiFiStatus_bcm(void);
#endif
