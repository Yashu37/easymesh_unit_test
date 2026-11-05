/* hwr_psp.h - plumbing for the platform_set_radio_pre_init harness (platform/banana-pi) */
#ifndef HWR_PSP_H
#define HWR_PSP_H
#include "hwr_defs.h"
extern "C" int hwr_platform_set_radio_pre_init(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam);
typedef struct {
	const char *test_name;
	unsigned index;                /* wifi_radio_index_t */
	int param_null;                /* 1: operationParam == NULL, 0: pointer to a fully poisoned runner slab (must not be touched) */
	int prefill;                   /* bytes of the log slot already used before the call */
	int calls;
	int expected_ret;
	int expect_log;                /* 1: one "platform_set_radio_pre_init:<line> " line per call must be appended */
} hwr_psp_case_t;
extern hwr_psp_case_t platform_set_radio_pre_init_suite[];
extern "C" void run_all_tests_platform_set_radio_pre_init(void);
#endif
