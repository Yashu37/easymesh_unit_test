/* hwr_fco.h - plumbing for the wifi_freq_to_op_class harness (platform/banana-pi) */
#ifndef HWR_FCO_H
#define HWR_FCO_H
#include "hwr_defs.h"
extern "C" UINT hwr_wifi_freq_to_op_class(UINT freq);
typedef struct {
	const char *test_name;
	unsigned freq;
	int calls;
	unsigned expected;             /* expected return value: the operating class, 0 for a known band without a class, (UINT)RETURN_ERR for no band */
} hwr_fco_case_t;
extern hwr_fco_case_t wifi_freq_to_op_class_suite[];
extern "C" void run_all_tests_wifi_freq_to_op_class(void);
#endif
