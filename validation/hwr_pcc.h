/* hwr_pcc.h - plumbing for the platform_get_country_code_default harness (platform/banana-pi) */
#ifndef HWR_PCC_H
#define HWR_PCC_H
#include "hwr_defs.h"
extern "C" int hwr_platform_get_country_code_default(char *code);
typedef struct {
	const char *test_name;
	int prefill;                   /* caller's buffer before the call: 0 zeros, 1 0xA5, 2 "DE" + NUL, 3 "XXXX" without NUL in the first 4 bytes... see runner */
	int null_code;
	int calls;
	int log_prefill;               /* bytes of the log slot already used */
	int expected_ret;
	const char *expected_code;     /* NULL = buffer untouched */
	int forked;
} hwr_pcc_case_t;
extern hwr_pcc_case_t platform_get_country_code_default_suite[];
extern "C" void run_all_tests_platform_get_country_code_default(void);
#endif
