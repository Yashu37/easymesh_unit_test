/* hwr_idg.h - plumbing for the wifi_getDownStreamGroupAddress harness (platform/intel) */
#ifndef HWR_IDG_H
#define HWR_IDG_H
#include "hwr_defs.h"
extern "C" INT hwr_int_wifi_getDownStreamGroupAddress(INT apIndex, BOOL *disabled);
typedef struct {
	const char *test_name;
	int ap_index;
	int out_mode;                  /* 0 enabled NULL, 1 pointer to the runner's BOOL slot (stale preset, poisoned around it) */
	int preset;                    /* value of *disabled before the call (never 0: the function must overwrite it) */
	int calls;
	int expected_ret;              /* NULL enabled: WIFI_HAL_ERROR; otherwise WIFI_HAL_SUCCESS */
	int expected_val;              /* *disabled after a successful call */
} hwr_idg_case_t;
extern hwr_idg_case_t int_wifi_getDownStreamGroupAddress_suite[];
extern "C" void run_all_tests_int_wifi_getDownStreamGroupAddress(void);
#endif
