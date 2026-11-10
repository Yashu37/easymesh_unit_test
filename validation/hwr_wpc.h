/* hwr_wpc.h - plumbing for the sg_wifi_hal_setApWpsCancel harness (src/wifi_hal.c) */
#ifndef HWR_WPC_H
#define HWR_WPC_H
#include "hwr_defs.h"
typedef struct { int calls; unsigned int last_index; } hwr_wpc_world_t;
extern hwr_wpc_world_t hwr_wpc_world;
extern "C" int hwr_sg_wifi_hal_setApWpsCancel(int ap_index);
typedef struct {
	const char *test_name;
	int ap_index;
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call */
	int expected_ret;
} hwr_wpc_case_t;
extern hwr_wpc_case_t sg_wifi_hal_setApWpsCancel_suite[];
extern "C" void run_all_tests_sg_wifi_hal_setApWpsCancel(void);
#endif
