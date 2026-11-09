/* hwr_rcd.h - plumbing for the raspberry-pi wifi_steering_clientDisconnect harness (platform/raspberry-pi) */
#ifndef HWR_RCD_H
#define HWR_RCD_H
#include "hwr_defs.h"
extern "C" INT hwr_rp_wifi_steering_clientDisconnect(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac, wifi_disconnectType_t type, UINT reason);
typedef struct {
	const char *test_name;
	unsigned group_index;
	int ap_index;
	int type;                      /* wifi_disconnectType_t value (any int) */
	unsigned reason;
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call */
	int expected_ret;
} hwr_rcd_case_t;
extern hwr_rcd_case_t rp_wifi_steering_clientDisconnect_suite[];
extern "C" void run_all_tests_rp_wifi_steering_clientDisconnect(void);
#endif
