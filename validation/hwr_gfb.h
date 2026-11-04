/* hwr_gfb.h - types / plumbing for the wifi_hal_getRadioOperatingFrequencyBand harness */
#ifndef HWR_GFB_H
#define HWR_GFB_H
#include "hwr_defs.h"
#define HWR_GFB_MAX_RADIOS 3
typedef struct { unsigned int rdk_radio_index; wifi_radio_operationParam_t oper_param; } hwr_gfb_radio_t;   /* REAL wifi_radio_operationParam_t */
typedef struct { unsigned int num_radios; hwr_gfb_radio_t *radio_info; } hwr_gfb_world_t;
extern hwr_gfb_world_t hwr_gfb_world;
extern "C" INT hwr_wifi_hal_getRadioOperatingFrequencyBand(INT radioIndex, CHAR *output_string);   /* renamed, see the handler file */

typedef struct { unsigned rdk_index; unsigned band; } hwr_gfb_rd_t;
typedef struct {
	const char *test_name;
	int nradios; hwr_gfb_rd_t r[HWR_GFB_MAX_RADIOS];
	int query; int null_out; int calls; int check_log;
	int expected_ret; const char *expected_out; int forked;       /* expected_out: NULL = output must stay untouched */
} hwr_gfb_case_t;
extern hwr_gfb_case_t wifi_hal_getRadioOperatingFrequencyBand_suite[];
extern "C" void run_all_tests_wifi_hal_getRadioOperatingFrequencyBand(void);
#endif
