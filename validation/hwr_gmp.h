/* hwr_gmp.h - plumbing for the wifi_getApManagementFramePowerControl harness (platform/banana-pi) */
#ifndef HWR_GMP_H
#define HWR_GMP_H
#include "hwr_defs.h"
extern "C" INT hwr_wifi_getApManagementFramePowerControl(INT apIndex, INT *output_dBm);
typedef struct {
	const char *test_name;
	int ap_index;
	int out_mode;                  /* 0 output_dBm NULL, 1 pointer to the runner's int slot (stale preset, poisoned around it) */
	int preset;                    /* value of *output_dBm before the call (never 0: the function must overwrite it) */
	int calls;
	int expected_ret;              /* NULL output_dBm: WIFI_HAL_ERROR; otherwise WIFI_HAL_SUCCESS */
	int expected_val;              /* *output_dBm after a successful call */
} hwr_gmp_case_t;
extern hwr_gmp_case_t wifi_getApManagementFramePowerControl_suite[];
extern "C" void run_all_tests_wifi_getApManagementFramePowerControl(void);
#endif
