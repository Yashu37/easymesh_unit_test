/* hwr_smp.h - plumbing for the wifi_setApManagementFramePowerControl harness (platform/banana-pi) */
#ifndef HWR_SMP_H
#define HWR_SMP_H
#include "hwr_defs.h"
extern "C" INT hwr_wifi_setApManagementFramePowerControl(INT apIndex, INT dBm);
typedef struct {
	const char *test_name;
	int ap_index;
	int dbm;                       /* management frame power in dBm passed */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call (the function logs nothing: it must stay as it was) */
	int expected_ret;
} hwr_smp_case_t;
extern hwr_smp_case_t wifi_setApManagementFramePowerControl_suite[];
extern "C" void run_all_tests_wifi_setApManagementFramePowerControl(void);
#endif
