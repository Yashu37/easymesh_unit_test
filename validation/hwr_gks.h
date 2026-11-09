/* hwr_gks.h - plumbing for the wifi_getRadioChannelStats harness (platform/banana-pi) */
#ifndef HWR_GKS_H
#define HWR_GKS_H
#include "hwr_defs.h"
#define GKS_N 64                   /* entries the runner's array has room for */
extern "C" INT hwr_wifi_getRadioChannelStats(INT radioIndex, wifi_channelStats_t *input_output_channelStats_array, INT array_size);
typedef struct {
	const char *test_name;
	int radio_index;
	int array_mode;                /* 0 NULL, 1 pointer to the runner's array (GKS_N entries, channel numbers pre-filled, stats stale) */
	int array_size;
	int calls;
	int expected_ret;              /* the stub has no channel statistics: it must report WIFI_HAL_ERROR, not success */
} hwr_gks_case_t;
extern hwr_gks_case_t wifi_getRadioChannelStats_suite[];
extern "C" void run_all_tests_wifi_getRadioChannelStats(void);
#endif
