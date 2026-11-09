/* hwr_isd.h - plumbing for the wifi_setDownStreamGroupAddress harness (platform/intel) */
#ifndef HWR_ISD_H
#define HWR_ISD_H
#include "hwr_defs.h"
extern "C" INT hwr_int_wifi_setDownStreamGroupAddress(INT apIndex, BOOL disabled);
typedef struct {
	const char *test_name;
	int ap_index;
	int enable;                    /* BOOL (unsigned char) value passed */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call (the function logs nothing: it must stay as it was) */
	int expected_ret;
} hwr_isd_case_t;
extern hwr_isd_case_t int_wifi_setDownStreamGroupAddress_suite[];
extern "C" void run_all_tests_int_wifi_setDownStreamGroupAddress(void);
#endif
