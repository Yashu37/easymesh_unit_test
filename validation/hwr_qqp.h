/* hwr_qqp.h - plumbing for the qc_wifi_setQamPlus harness (platform/qualcomm) */
#ifndef HWR_QQP_H
#define HWR_QQP_H
#include "hwr_defs.h"
extern "C" int hwr_qc_wifi_setQamPlus(void *radioIndex);
typedef struct {
	const char *test_name;
	int in_mode;                 /* 0 NULL, 1 pointer to a fully POISONED runner slab (must not be touched), 2 dangling pointer 0xdeadbeef */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call (the function logs nothing: it must stay as it was) */
	int expected_ret;
} hwr_qqp_case_t;
extern hwr_qqp_case_t qc_wifi_setQamPlus_suite[];
extern "C" void run_all_tests_qc_wifi_setQamPlus(void);
#endif
