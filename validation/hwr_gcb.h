/* hwr_gcb.h - types / plumbing for the wifi_hal_getRadioOperatingChannelBandwidth harness */
#ifndef HWR_GCB_H
#define HWR_GCB_H
#include "hwr_defs.h"
#define HWR_GCB_MAX_RADIOS 3
typedef struct { unsigned int rdk_radio_index; wifi_radio_operationParam_t oper_param; } hwr_gcb_radio_t;   /* REAL wifi_radio_operationParam_t */
typedef struct { unsigned int num_radios; hwr_gcb_radio_t *radio_info; } hwr_gcb_world_t;
extern hwr_gcb_world_t hwr_gcb_world;
extern "C" INT hwr_wifi_hal_getRadioOperatingChannelBandwidth(INT radioIndex, CHAR *output_string);   /* renamed, see the handler file */

typedef struct { unsigned rdk_index; unsigned width; } hwr_gcb_rd_t;
typedef struct {
	const char *test_name;
	int nradios; hwr_gcb_rd_t r[HWR_GCB_MAX_RADIOS];
	int query; int null_out; int calls; int check_log;
	int expected_ret; const char *expected_out; int forked;       /* expected_out: NULL = output must stay untouched */
} hwr_gcb_case_t;
extern hwr_gcb_case_t wifi_hal_getRadioOperatingChannelBandwidth_suite[];
extern "C" void run_all_tests_wifi_hal_getRadioOperatingChannelBandwidth(void);
#endif
