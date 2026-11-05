/* hwr_nsm.h - plumbing for the nvram_get_current_security_mode harness (platform/banana-pi) */
#ifndef HWR_NSM_H
#define HWR_NSM_H
#include "hwr_defs.h"
#include <stdbool.h>
extern "C" int hwr_nvram_get_current_security_mode(wifi_security_modes_t *security_mode, int vap_index);
typedef struct {
	const char *test_name;
	int vap_index;
	int out_null;                  /* security_mode == NULL */
	int calls;
	int prefill;                   /* bytes of the log slot already used */
	int expected_ret;
} hwr_nsm_case_t;
extern hwr_nsm_case_t nvram_get_current_security_mode_suite[];
extern "C" void run_all_tests_nvram_get_current_security_mode(void);
#endif
