/* hwr_rgi.h - plumbing for the wifi_getApInterworkingServiceEnable harness (platform/raspberry-pi) */
#ifndef HWR_RGI_H
#define HWR_RGI_H
#include "hwr_defs.h"
extern "C" INT hwr_rp_wifi_getApInterworkingServiceEnable(INT apIndex, BOOL *output_bool);
typedef struct {
	const char *test_name;
	int ap_index;
	int out_mode;                  /* 0 enabled NULL, 1 pointer to the runner's BOOL slot (stale preset, poisoned around it) */
	int preset;                    /* value of *output_bool before the call (never 0: the function must overwrite it) */
	int calls;
	int expected_ret;              /* NULL enabled: WIFI_HAL_SUCCESS; otherwise WIFI_HAL_SUCCESS */
	int expected_val;              /* *output_bool after a successful call */
} hwr_rgi_case_t;
extern hwr_rgi_case_t rp_wifi_getApInterworkingServiceEnable_suite[];
extern "C" void run_all_tests_rp_wifi_getApInterworkingServiceEnable(void);
#endif
