/* hwr_ici.h - plumbing for the wifi_setCountryIe harness (platform/intel) */
#ifndef HWR_ICI_H
#define HWR_ICI_H
#include "hwr_defs.h"
extern "C" INT hwr_int_wifi_setCountryIe(INT apIndex, BOOL enabled);
typedef struct {
	const char *test_name;
	int ap_index;
	int enable;                    /* BOOL (unsigned char) value passed */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call (the function logs nothing: it must stay as it was) */
	int expected_ret;
} hwr_ici_case_t;
extern hwr_ici_case_t int_wifi_setCountryIe_suite[];
extern "C" void run_all_tests_int_wifi_setCountryIe(void);
#endif
