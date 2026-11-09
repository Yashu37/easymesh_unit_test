/* hwr_gpa.h - plumbing for the wifi_getProxyArp harness (platform/banana-pi) */
#ifndef HWR_GPA_H
#define HWR_GPA_H
#include "hwr_defs.h"
extern "C" INT hwr_wifi_getProxyArp(INT apIndex, BOOL *enabled);
typedef struct {
	const char *test_name;
	int ap_index;
	int out_mode;                  /* 0 enabled NULL, 1 pointer to the runner's BOOL slot (stale preset, poisoned around it) */
	int preset;                    /* value of *enabled before the call (never 0: the function must overwrite it) */
	int calls;
	int expected_ret;              /* NULL enabled: WIFI_HAL_ERROR; otherwise WIFI_HAL_SUCCESS */
	int expected_val;              /* *enabled after a successful call */
} hwr_gpa_case_t;
extern hwr_gpa_case_t wifi_getProxyArp_suite[];
extern "C" void run_all_tests_wifi_getProxyArp(void);
#endif
