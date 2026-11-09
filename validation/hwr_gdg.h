/* hwr_gdg.h - plumbing for the wifi_getDownStreamGroupAddress harness (platform/banana-pi) */
#ifndef HWR_GDG_H
#define HWR_GDG_H
#include "hwr_defs.h"
extern "C" INT hwr_wifi_getDownStreamGroupAddress(INT apIndex, BOOL *disabled);
typedef struct {
	const char *test_name;
	int ap_index;
	int out_mode;                  /* 0 disabled NULL, 1 pointer to the runner's BOOL slot (stale preset, poisoned around it) */
	int preset;                    /* value of *disabled before the call (never 0: the function must overwrite it) */
	int calls;
	int expected_ret;              /* NULL disabled: WIFI_HAL_ERROR; otherwise WIFI_HAL_SUCCESS */
	int expected_val;              /* *disabled after a successful call */
} hwr_gdg_case_t;
extern hwr_gdg_case_t wifi_getDownStreamGroupAddress_suite[];
extern "C" void run_all_tests_wifi_getDownStreamGroupAddress(void);
#endif
