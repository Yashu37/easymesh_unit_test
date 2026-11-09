/* hwr_rdb.h - plumbing for the wifi_setRadioDfsAtBootUpEnable harness (platform/raspberry-pi) */
#ifndef HWR_RDB_H
#define HWR_RDB_H
#include "hwr_defs.h"
extern "C" INT hwr_rp_wifi_setRadioDfsAtBootUpEnable(INT radioIndex, BOOL enable);
typedef struct {
	const char *test_name;
	int radio_index;
	int enable;                    /* BOOL (unsigned char) value passed */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call (the function logs nothing: it must stay as it was) */
	int expected_ret;
} hwr_rdb_case_t;
extern hwr_rdb_case_t rp_wifi_setRadioDfsAtBootUpEnable_suite[];
extern "C" void run_all_tests_rp_wifi_setRadioDfsAtBootUpEnable(void);
#endif
