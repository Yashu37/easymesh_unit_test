/* hwr_idb.h - plumbing for the wifi_setRadioDfsAtBootUpEnable harness (platform/intel) */
#ifndef HWR_IDB_H
#define HWR_IDB_H
#include "hwr_defs.h"
extern "C" INT hwr_int_wifi_setRadioDfsAtBootUpEnable(INT radioIndex, BOOL enabled);
typedef struct {
	const char *test_name;
	int radio_index;
	int enable;                    /* BOOL (unsigned char) value passed */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call (the function logs nothing: it must stay as it was) */
	int expected_ret;
} hwr_idb_case_t;
extern hwr_idb_case_t int_wifi_setRadioDfsAtBootUpEnable_suite[];
extern "C" void run_all_tests_int_wifi_setRadioDfsAtBootUpEnable(void);
#endif
