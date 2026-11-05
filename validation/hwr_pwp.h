/* hwr_pwp.h - plumbing for the platform_get_wps_pin_default harness (platform/banana-pi) */
#ifndef HWR_PWP_H
#define HWR_PWP_H
#include "hwr_defs.h"
extern "C" int hwr_platform_get_wps_pin_default(char *pin);
extern "C" int hwr_pwp_nvram(char *in, char *out);
typedef struct { int nvram_ret; const char *nvram_val; int calls; char key[32]; } hwr_pwp_rec_t;
extern hwr_pwp_rec_t hwr_pwp_rec;
typedef struct {
	const char *test_name;
	int nvram_ret; const char *nvram_val;
	int prefill;                   /* caller's buffer before the call: 0 = zeros (as the callers do), 1 = 0xA5 (uninitialised, no NUL) */
	int null_pin;
	int expected_ret;
	const char *expected_pin;      /* NULL = buffer untouched */
	int forked;
} hwr_pwp_case_t;
extern hwr_pwp_case_t platform_get_wps_pin_default_suite[];
extern "C" void run_all_tests_platform_get_wps_pin_default(void);
#endif
