#ifndef HWR_GTS_H
#define HWR_GTS_H
#include "hwr_defs.h"
extern "C" INT hwr_wifi_hal_getSSIDTrafficStats2(INT ssidIndex, wifi_ssidTrafficStats2_t *output_struct);   /* renamed, see the handler file */
typedef struct {
	const char *test_name;
	int ssid_index; int callee_ret; int null_out;
	int calls; int check_log;
	int expected_ret; int forked;
} hwr_gts_case_t;
extern hwr_gts_case_t wifi_hal_getSSIDTrafficStats2_suite[];
extern "C" void run_all_tests_wifi_hal_getSSIDTrafficStats2(void);
typedef struct { int calls; INT ssid; wifi_ssidTrafficStats2_t *out; } hwr_gts_rec_t;
extern hwr_gts_rec_t hwr_gts_rec;
void hwr_gts_configure(int callee_ret);
#endif
