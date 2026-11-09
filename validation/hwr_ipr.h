/* hwr_ipr.h - plumbing for the intel wifi_pushApRoamingConsortiumElement harness (platform/intel) */
#ifndef HWR_IPR_H
#define HWR_IPR_H
#include "hwr_defs.h"
extern "C" INT hwr_int_wifi_pushApRoamingConsortiumElement(INT apIndex, wifi_roamingConsortiumElement_t *infoElement);
typedef struct {
	const char *test_name;
	int ap_index;
	int out_mode;                  /* 0 NULL, 1 pointer to the runner's structure (stale 0x5A bytes, the whole slab POISONED around the call), 2 dangling 0xdeadbeef */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call (the function logs nothing: it must stay as it was) */
	int expected_ret;
} hwr_ipr_case_t;
extern hwr_ipr_case_t int_wifi_pushApRoamingConsortiumElement_suite[];
extern "C" void run_all_tests_int_wifi_pushApRoamingConsortiumElement(void);
#endif
