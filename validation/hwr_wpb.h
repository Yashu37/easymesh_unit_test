/* hwr_wpb.h - plumbing for the sg_wifi_hal_setApWpsButtonPush harness (src/wifi_hal.c) */
#ifndef HWR_WPB_H
#define HWR_WPB_H
#include "hwr_defs.h"
typedef struct { int calls; unsigned int last_index; } hwr_wpb_world_t;
extern hwr_wpb_world_t hwr_wpb_world;
extern "C" int hwr_sg_wifi_hal_setApWpsButtonPush(int ap_index);
typedef struct {
	const char *test_name;
	int ap_index;
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call */
	int expected_ret;
} hwr_wpb_case_t;
extern hwr_wpb_case_t sg_wifi_hal_setApWpsButtonPush_suite[];
extern "C" void run_all_tests_sg_wifi_hal_setApWpsButtonPush(void);
#endif
