/* hwr_wwe.h - plumbing for the sg_wifi_hal_wps_event harness (src/wifi_hal.c) */
#ifndef HWR_WWE_H
#define HWR_WWE_H
#include "hwr_defs.h"
/* wifi_wps_event_t of src/wifi_hal_rdk_framework.h:117-121 */
typedef struct {
	unsigned int    vap_index;
	unsigned int    event;
	unsigned char   *wps_data;
} __attribute__((__packed__)) wifi_wps_event_t;
typedef struct { int getter_calls; int hook_calls; int hook_present; int hook_ret; wifi_wps_event_t last; } hwr_wwe_world_t;
extern hwr_wwe_world_t hwr_wwe_world;
extern "C" int hwr_sg_wifi_hal_wps_event(wifi_wps_event_t data);
typedef struct {
	const char *test_name;
	int hook_present;
	int hook_ret;                  /* what the platform hook returns */
	unsigned vap_index;
	unsigned event;
	int data_mode;                 /* wps_data: 0 NULL, 1 pointer to a fully POISONED 64-byte runner slab (the wrapper must not touch it), 2 dangling 0xdeadbeef */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call */
	int expected_ret;
} hwr_wwe_case_t;
extern hwr_wwe_case_t sg_wifi_hal_wps_event_suite[];
extern "C" void run_all_tests_sg_wifi_hal_wps_event(void);
#endif
