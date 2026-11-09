/* hwr_sl2.h - plumbing for the wifi_setLayer2TrafficInspectionFiltering harness (platform/banana-pi) */
#ifndef HWR_SL2_H
#define HWR_SL2_H
#include "hwr_defs.h"
extern "C" INT hwr_wifi_setLayer2TrafficInspectionFiltering(INT apIndex, BOOL enabled);
typedef struct {
	const char *test_name;
	int ap_index;
	int enable;                    /* BOOL (unsigned char) value passed */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call (the function logs nothing: it must stay as it was) */
	int expected_ret;
} hwr_sl2_case_t;
extern hwr_sl2_case_t wifi_setLayer2TrafficInspectionFiltering_suite[];
extern "C" void run_all_tests_wifi_setLayer2TrafficInspectionFiltering(void);
#endif
