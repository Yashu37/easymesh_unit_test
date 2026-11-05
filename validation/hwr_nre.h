/* hwr_nre.h - plumbing for the nvram_get_radio_enable_status harness (platform/banana-pi) */
#ifndef HWR_NRE_H
#define HWR_NRE_H
#include "hwr_defs.h"
#include <stdbool.h>
extern "C" int hwr_nvram_get_radio_enable_status(bool *radio_enable, int radio_index);
typedef struct {
	const char *test_name;
	int radio_index;
	int out_null;                  /* radio_enable == NULL */
	int calls;
	int prefill;                   /* bytes of the log slot already used */
	int expected_ret;
} hwr_nre_case_t;
extern hwr_nre_case_t nvram_get_radio_enable_status_suite[];
extern "C" void run_all_tests_nvram_get_radio_enable_status(void);
#endif
