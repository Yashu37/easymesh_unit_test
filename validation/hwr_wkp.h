/* hwr_wkp.h - plumbing for the sg_wifi_hal_get_default_keypassphrase harness (src/wifi_hal.c) */
#ifndef HWR_WKP_H
#define HWR_WKP_H
#include "hwr_defs.h"
typedef struct { int getter_calls; int hook_calls; int hook_present; int hook_ret; const char *last_pw; int last_vap; } hwr_wkp_world_t;
extern hwr_wkp_world_t hwr_wkp_world;
extern "C" int hwr_sg_wifi_hal_get_default_keypassphrase(char *password, int vap_index);
typedef struct {
	const char *test_name;
	int hook_present;
	int hook_ret;                  /* what the platform hook returns */
	int pw_mode;                 /* 0 NULL, 1 pointer to a fully POISONED 64-byte runner slab (the wrapper must not touch it), 2 dangling pointer 0xdeadbeef */
	int vap_index;
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call */
	int expected_ret;
} hwr_wkp_case_t;
extern hwr_wkp_case_t sg_wifi_hal_get_default_keypassphrase_suite[];
extern "C" void run_all_tests_sg_wifi_hal_get_default_keypassphrase(void);
#endif
