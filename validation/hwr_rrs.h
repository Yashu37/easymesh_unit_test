/* hwr_rrs.h - plumbing for the raspberry-pi wifi_getApDeviceRSSI harness (platform/raspberry-pi) */
#ifndef HWR_RRS_H
#define HWR_RRS_H
#include "hwr_defs.h"
extern "C" INT hwr_rp_wifi_getApDeviceRSSI(INT ap_index, CHAR *MAC, INT *output_RSSI);
typedef struct {
	const char *test_name;
	int ap_index;
	int mac_mode;                  /* 0 NULL, 1 a fully POISONED 18-byte slab (must not be read), 2 dangling pointer 0xdeadbeef */
	int out_mode;                  /* 0 NULL, 1 the runner's INT slot inside a canary slab (the whole slab POISONED: must not be read or written), 2 dangling pointer */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call */
	int expected_ret;
} hwr_rrs_case_t;
extern hwr_rrs_case_t rp_wifi_getApDeviceRSSI_suite[];
extern "C" void run_all_tests_rp_wifi_getApDeviceRSSI(void);
#endif
