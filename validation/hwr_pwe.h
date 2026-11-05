/* hwr_pwe.h - plumbing for the platform_wps_event harness (platform/banana-pi) */
#ifndef HWR_PWE_H
#define HWR_PWE_H
#include "hwr_defs.h"
/* src/wifi_hal_rdk_framework.h:117-121 verbatim */
typedef struct {
    unsigned int    vap_index;
    unsigned int    event;
    unsigned char   *wps_data;
} __attribute__((__packed__)) wifi_wps_event_t;
extern "C" int hwr_platform_wps_event(wifi_wps_event_t data);
typedef struct {
	const char *test_name;
	unsigned vap_index;
	unsigned event;
	int data_mode;                 /* wps_data: 0 NULL, 1 pointer to a fully POISONED runner slab (must not be read), 2 dangling pointer 0xdeadbeef */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call */
	int expected_ret;
	int expect_log;                /* 1: one "platform_wps_event:<line> " line per call must be appended */
} hwr_pwe_case_t;
extern hwr_pwe_case_t platform_wps_event_suite[];
extern "C" void run_all_tests_platform_wps_event(void);
#endif
