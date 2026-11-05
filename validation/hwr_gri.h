/* hwr_gri.h - types / plumbing for the wifi_hal_getRadioIfName harness */
#ifndef HWR_GRI_H
#define HWR_GRI_H
#include "hwr_defs.h"
typedef struct { unsigned int num_radios; } hwr_gri_world_t;
extern hwr_gri_world_t hwr_gri_world;
extern "C" INT hwr_wifi_hal_getRadioIfName(INT radioIndex, CHAR *output_string);   /* renamed, see the handler file */
typedef struct {
	const char *test_name;
	unsigned num_radios; int index; int null_out; int calls; int check_log;
	int expected_ret; const char *expected_out; int forked;       /* expected_out: NULL = output must stay untouched */
} hwr_gri_case_t;
extern hwr_gri_case_t wifi_hal_getRadioIfName_suite[];
extern "C" void run_all_tests_wifi_hal_getRadioIfName(void);
#endif
