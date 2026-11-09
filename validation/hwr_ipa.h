/* hwr_ipa.h - plumbing for the wifi_setProxyArp harness (platform/intel) */
#ifndef HWR_IPA_H
#define HWR_IPA_H
#include "hwr_defs.h"
extern "C" INT hwr_int_wifi_setProxyArp(INT apIndex, BOOL enabled);
typedef struct {
	const char *test_name;
	int ap_index;
	int enable;                    /* BOOL (unsigned char) value passed */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call (the function logs nothing: it must stay as it was) */
	int expected_ret;
} hwr_ipa_case_t;
extern hwr_ipa_case_t int_wifi_setProxyArp_suite[];
extern "C" void run_all_tests_int_wifi_setProxyArp(void);
#endif
