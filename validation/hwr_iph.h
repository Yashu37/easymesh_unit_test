/* hwr_iph.h - plumbing for the wifi_pushApHotspotElement harness (platform/intel) */
#ifndef HWR_IPH_H
#define HWR_IPH_H
#include "hwr_defs.h"
extern "C" INT hwr_int_wifi_pushApHotspotElement(INT apIndex, BOOL enabled);
typedef struct {
	const char *test_name;
	int ap_index;
	int enable;                    /* BOOL (unsigned char) value passed */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call (the function logs nothing: it must stay as it was) */
	int expected_ret;
} hwr_iph_case_t;
extern hwr_iph_case_t int_wifi_pushApHotspotElement_suite[];
extern "C" void run_all_tests_int_wifi_pushApHotspotElement(void);
#endif
