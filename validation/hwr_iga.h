/* hwr_iga.h - plumbing for the int_wifi_applyGASConfiguration harness (platform/intel) */
#ifndef HWR_IGA_H
#define HWR_IGA_H
#include "hwr_defs.h"
extern "C" INT hwr_int_wifi_applyGASConfiguration(wifi_GASConfiguration_t *input_struct);
typedef struct {
	const char *test_name;
	int in_mode;                 /* 0 NULL, 1 pointer to a fully POISONED runner slab (must not be touched), 2 dangling pointer 0xdeadbeef */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call (the function logs nothing: it must stay as it was) */
	int expected_ret;
} hwr_iga_case_t;
extern hwr_iga_case_t int_wifi_applyGASConfiguration_suite[];
extern "C" void run_all_tests_int_wifi_applyGASConfiguration(void);
#endif
