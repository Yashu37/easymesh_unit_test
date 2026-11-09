/* hwr_spc.h - plumbing for the wifi_setP2PCrossConnect harness (platform/banana-pi) */
#ifndef HWR_SPC_H
#define HWR_SPC_H
#include "hwr_defs.h"
extern "C" INT hwr_wifi_setP2PCrossConnect(INT apIndex, BOOL enable);
typedef struct {
	const char *test_name;
	int ap_index;
	int enable;                    /* BOOL (unsigned char) value passed */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call (the function logs nothing: it must stay as it was) */
	int expected_ret;
} hwr_spc_case_t;
extern hwr_spc_case_t wifi_setP2PCrossConnect_suite[];
extern "C" void run_all_tests_wifi_setP2PCrossConnect(void);
#endif
