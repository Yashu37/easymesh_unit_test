/* hwr_sdg.h - plumbing for the wifi_setDownStreamGroupAddress harness (platform/banana-pi) */
#ifndef HWR_SDG_H
#define HWR_SDG_H
#include "hwr_defs.h"
extern "C" INT hwr_wifi_setDownStreamGroupAddress(INT apIndex, BOOL enable);
typedef struct {
	const char *test_name;
	int ap_index;
	int enable;                    /* BOOL (unsigned char) value passed */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call (the function logs nothing: it must stay as it was) */
	int expected_ret;
} hwr_sdg_case_t;
extern hwr_sdg_case_t wifi_setDownStreamGroupAddress_suite[];
extern "C" void run_all_tests_wifi_setDownStreamGroupAddress(void);
#endif
