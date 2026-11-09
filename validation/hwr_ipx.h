/* hwr_ipx.h - plumbing for the wifi_setP2PCrossConnect harness (platform/intel) */
#ifndef HWR_IPX_H
#define HWR_IPX_H
#include "hwr_defs.h"
extern "C" INT hwr_int_wifi_setP2PCrossConnect(INT apIndex, BOOL disabled);
typedef struct {
	const char *test_name;
	int ap_index;
	int enable;                    /* BOOL (unsigned char) value passed */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call (the function logs nothing: it must stay as it was) */
	int expected_ret;
} hwr_ipx_case_t;
extern hwr_ipx_case_t int_wifi_setP2PCrossConnect_suite[];
extern "C" void run_all_tests_int_wifi_setP2PCrossConnect(void);
#endif
