/* hwr_wpi.h - plumbing for the sg_wifi_hal_pre_init harness (src/wifi_hal.c) */
#ifndef HWR_WPI_H
#define HWR_WPI_H
#include "hwr_defs.h"
typedef struct { int getter_calls; int hook_calls; int hook_present; } hwr_wpi_world_t;
extern hwr_wpi_world_t hwr_wpi_world;
extern "C" int hwr_sg_wifi_hal_pre_init(void);
typedef struct {
	const char *test_name;
	int hook_present;              /* get_platform_pre_init_fn() returns a hook (1) or NULL (0) */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call */
	int expected_ret;
} hwr_wpi_case_t;
extern hwr_wpi_case_t sg_wifi_hal_pre_init_suite[];
extern "C" void run_all_tests_sg_wifi_hal_pre_init(void);
#endif
