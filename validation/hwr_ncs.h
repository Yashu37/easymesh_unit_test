/* hwr_ncs.h - plumbing for the nvram_get_current_ssid harness (platform/banana-pi) */
#ifndef HWR_NCS_H
#define HWR_NCS_H
#include "hwr_defs.h"
extern "C" int hwr_nvram_get_current_ssid(char *l_ssid, int vap_index);
typedef struct {
	const char *test_name;
	int vap_index;
	int prefill;                   /* 0 zeros, 1 0xA5 (uninitialised) */
	int null_ssid;
	int calls;
	int log_prefill;
	int expected_ret;
	const char *expected_ssid;     /* NULL = buffer untouched (the non-MLO build; the MLO build always expects the constant name) */
	int forked;
} hwr_ncs_case_t;
extern hwr_ncs_case_t nvram_get_current_ssid_suite[];
extern "C" void run_all_tests_nvram_get_current_ssid(void);
#endif
