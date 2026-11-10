/* hwr_wpo.h - plumbing for the sg_wifi_hal_post_init harness (src/wifi_hal.c, both build variants: HAL_IPC and plain) */
#ifndef HWR_WPO_H
#define HWR_WPO_H
#include "hwr_defs.h"
struct hwr_wpo_post_init_struct { char bytes[48]; };          /* STAND-IN for wifi_hal_post_init_t: the function never reads it */
typedef struct hwr_wpo_post_init_struct wifi_hal_post_init_t;
typedef struct { int getter_calls; int hook_calls; int hook_present; const void *last_arg; } hwr_wpo_world_t;
extern hwr_wpo_world_t hwr_wpo_world;
extern "C" int hwr_sg_wifi_hal_post_init_ipc(wifi_hal_post_init_t *post_init_struct);
extern "C" int hwr_sg_wifi_hal_post_init_vap(wifi_vap_info_map_t *vap_map);
typedef struct {
	const char *test_name;
	int variant;                   /* 0 = HAL_IPC variant (wifi_hal_post_init_t *), 1 = plain variant (wifi_vap_info_map_t *) */
	int hook_present;
	int arg_mode;                  /* 0 NULL, 1 pointer to a fully POISONED runner slab (the function must not read or write it), 2 dangling pointer 0xdeadbeef */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call */
	int expected_ret;
} hwr_wpo_case_t;
extern hwr_wpo_case_t sg_wifi_hal_post_init_suite[];
extern "C" void run_all_tests_sg_wifi_hal_post_init(void);
#endif
