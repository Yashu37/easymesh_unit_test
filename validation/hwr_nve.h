/* hwr_nve.h - plumbing for the nvram_get_vap_enable_status harness (platform/banana-pi) */
#ifndef HWR_NVE_H
#define HWR_NVE_H
#include "hwr_defs.h"
#include <stdbool.h>
extern "C" int hwr_nvram_get_vap_enable_status(bool *vap_enable, int vap_index);
typedef struct {
	const char *test_name;
	int vap_index;
	int out_null;                  /* vap_enable == NULL */
	int calls;
	int prefill;                   /* bytes of the log slot already used */
	int expected_ret;
} hwr_nve_case_t;
extern hwr_nve_case_t nvram_get_vap_enable_status_suite[];
extern "C" void run_all_tests_nvram_get_vap_enable_status(void);
#endif
