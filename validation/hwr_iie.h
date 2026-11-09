/* hwr_iie.h - plumbing for the intel wifi_getApInterworkingElement harness (platform/intel) */
#ifndef HWR_IIE_H
#define HWR_IIE_H
#include "hwr_defs.h"
extern "C" INT hwr_int_wifi_getApInterworkingElement(INT apIndex, wifi_InterworkingElement_t *output_struct);
typedef struct {
	const char *test_name;
	int ap_index;
	int out_mode;                  /* 0 NULL, 1 pointer to the runner's structure (stale 0x5A bytes, the whole slab POISONED around the call), 2 dangling 0xdeadbeef */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call (the function logs nothing: it must stay as it was) */
	int expected_ret;
} hwr_iie_case_t;
extern hwr_iie_case_t int_wifi_getApInterworkingElement_suite[];
extern "C" void run_all_tests_int_wifi_getApInterworkingElement(void);
#endif
