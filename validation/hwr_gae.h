/* hwr_gae.h - plumbing for the wifi_getApEnable harness (platform/banana-pi) */
#ifndef HWR_GAE_H
#define HWR_GAE_H
#include "hwr_defs.h"
extern "C" INT hwr_wifi_getApEnable(INT apIndex, BOOL *output_bool);
typedef struct {
	const char *test_name;
	int ap_index;
	int out_mode;                  /* 0 output_bool NULL, 1 pointer to the runner's BOOL slot (stale preset, poisoned around it) */
	int preset;                    /* value of *output_bool before the call (never 0: the function must overwrite it) */
	int calls;
	int expected_ret;              /* NULL output_bool: WIFI_HAL_ERROR; otherwise WIFI_HAL_SUCCESS */
	int expected_val;              /* *output_bool after a successful call */
} hwr_gae_case_t;
extern hwr_gae_case_t wifi_getApEnable_suite[];
extern "C" void run_all_tests_wifi_getApEnable(void);
#endif
