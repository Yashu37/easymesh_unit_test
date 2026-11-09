/* hwr_sbl.h - plumbing for the wifi_setBssLoad harness (platform/banana-pi) */
#ifndef HWR_SBL_H
#define HWR_SBL_H
#include "hwr_defs.h"
extern "C" INT hwr_wifi_setBssLoad(INT apIndex, BOOL enable);
typedef struct {
	const char *test_name;
	int ap_index;
	int enable;                    /* BOOL (unsigned char) value passed */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call (the function logs nothing: it must stay as it was) */
	int expected_ret;
} hwr_sbl_case_t;
extern hwr_sbl_case_t wifi_setBssLoad_suite[];
extern "C" void run_all_tests_wifi_setBssLoad(void);
#endif
