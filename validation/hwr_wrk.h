/* hwr_wrk.h - plumbing for the sg_wifi_hal_get_default_radius_key harness (src/wifi_hal.c) */
#ifndef HWR_WRK_H
#define HWR_WRK_H
#include "hwr_defs.h"
typedef struct { int getter_calls; int hook_calls; int hook_present; int hook_ret; const char *last_key; } hwr_wrk_world_t;
extern hwr_wrk_world_t hwr_wrk_world;
extern "C" int hwr_sg_wifi_hal_get_default_radius_key(char *radius_key);
typedef struct {
	const char *test_name;
	int hook_present;
	int hook_ret;                  /* what the platform hook returns */
	int key_mode;                 /* 0 NULL, 1 pointer to a fully POISONED 64-byte runner slab (the wrapper must not touch it), 2 dangling pointer 0xdeadbeef */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call */
	int expected_ret;
} hwr_wrk_case_t;
extern hwr_wrk_case_t sg_wifi_hal_get_default_radius_key_suite[];
extern "C" void run_all_tests_sg_wifi_hal_get_default_radius_key(void);
#endif
