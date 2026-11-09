/* hwr_pah.h - plumbing for the wifi_pushApHotspotElement harness (platform/banana-pi) */
#ifndef HWR_PAH_H
#define HWR_PAH_H
#include "hwr_defs.h"
extern "C" INT hwr_wifi_pushApHotspotElement(INT apIndex, BOOL enable);
typedef struct {
	const char *test_name;
	int ap_index;
	int enable;                    /* BOOL (unsigned char) value passed */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call (the function logs nothing: it must stay as it was) */
	int expected_ret;
} hwr_pah_case_t;
extern hwr_pah_case_t wifi_pushApHotspotElement_suite[];
extern "C" void run_all_tests_wifi_pushApHotspotElement(void);
#endif
