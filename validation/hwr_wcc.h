/* hwr_wcc.h - plumbing for the sg_wifi_hal_get_default_country_code harness (src/wifi_hal.c) */
#ifndef HWR_WCC_H
#define HWR_WCC_H
#include "hwr_defs.h"
typedef struct { int getter_calls; int hook_calls; int hook_present; int hook_ret; const char *last_code; } hwr_wcc_world_t;
extern hwr_wcc_world_t hwr_wcc_world;
extern "C" int hwr_sg_wifi_hal_get_default_country_code(char *code);
typedef struct {
	const char *test_name;
	int hook_present;
	int hook_ret;                  /* what the platform hook returns */
	int code_mode;                 /* 0 NULL, 1 pointer to a fully POISONED 64-byte runner slab (the wrapper must not touch it), 2 dangling pointer 0xdeadbeef */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call */
	int expected_ret;
} hwr_wcc_case_t;
extern hwr_wcc_case_t sg_wifi_hal_get_default_country_code_suite[];
extern "C" void run_all_tests_sg_wifi_hal_get_default_country_code(void);
#endif
