/* hwr_ia2.h - plumbing for the intel wifi_allow2G80211ax harness (platform/intel) */
#ifndef HWR_IA2_H
#define HWR_IA2_H
#include "hwr_defs.h"
extern "C" int hwr_int_wifi_allow2G80211ax(bool enable);
typedef struct {
	const char *test_name;
	int enable;                    /* 0 -> false, anything else -> true (the parameter is a C++ bool) */
	int calls;
	int alternate;                 /* 1: flip enable on every call */
	int prefill;                   /* bytes of the log slot already used before the call (the function logs nothing: it must stay as it was) */
	int expected_ret;
} hwr_ia2_case_t;
extern hwr_ia2_case_t int_wifi_allow2G80211ax_suite[];
extern "C" void run_all_tests_int_wifi_allow2G80211ax(void);
#endif
