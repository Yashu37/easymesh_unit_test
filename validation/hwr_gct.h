/* hwr_gct.h - types / plumbing for the wifi_hal_getRadioCountryCode harness */
#ifndef HWR_GCT_H
#define HWR_GCT_H
#include "hwr_defs.h"
#define HWR_GCT_MAX_RADIOS 3
typedef struct { unsigned int rdk_radio_index; wifi_radio_operationParam_t oper_param; } hwr_gct_radio_t;   /* REAL wifi_radio_operationParam_t */
typedef struct { unsigned int num_radios; hwr_gct_radio_t *radio_info; } hwr_gct_world_t;
extern hwr_gct_world_t hwr_gct_world;
extern "C" INT hwr_wifi_hal_getRadioCountryCode(INT radioIndex, CHAR *output_string);   /* renamed, see the handler file */

typedef struct { unsigned rdk_index; int code; } hwr_gct_rd_t;
typedef struct {
	const char *test_name;
	int nradios; hwr_gct_rd_t r[HWR_GCT_MAX_RADIOS];
	int query; int null_out; int calls; int check_log;
	int expected_ret; const char *expected_out; int forked;       /* expected_out: NULL = output must stay untouched */
	int all_codes;                                                /* 1: ignore radios, check every wifi_countrycode_type_t value */
} hwr_gct_case_t;
typedef struct { int code; const char *str; } hwr_gct_code_t;
extern hwr_gct_code_t hwr_gct_all[];
extern int hwr_gct_all_n;
extern hwr_gct_case_t wifi_hal_getRadioCountryCode_suite[];
extern "C" void run_all_tests_wifi_hal_getRadioCountryCode(void);
#endif
