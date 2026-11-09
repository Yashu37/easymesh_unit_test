/* hwr_imc.h - plumbing for the intel wifi_setApMacAddressControlMode harness (platform/intel) */
#ifndef HWR_IMC_H
#define HWR_IMC_H
#include "hwr_defs.h"
extern "C" INT hwr_int_wifi_setApMacAddressControlMode(INT apIndex, INT filterMode);
typedef struct {
	const char *test_name;
	int ap_index;
	int filter_mode;
	int calls;
	int alternate;                 /* 1: add 1 to filter_mode on every call */
	int prefill;                   /* bytes of the log slot already used before the call (the function logs nothing: it must stay as it was) */
	int expected_ret;
} hwr_imc_case_t;
extern hwr_imc_case_t int_wifi_setApMacAddressControlMode_suite[];
extern "C" void run_all_tests_int_wifi_setApMacAddressControlMode(void);
#endif
