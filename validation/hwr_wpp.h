/* hwr_wpp.h - plumbing for the sg_wifi_hal_setApWpsPin harness (src/wifi_hal.c) */
#ifndef HWR_WPP_H
#define HWR_WPP_H
#include "hwr_defs.h"
typedef struct { int calls; unsigned int last_index; const char *last_pin; int ret; } hwr_wpp_world_t;
extern hwr_wpp_world_t hwr_wpp_world;
extern "C" int hwr_sg_wifi_hal_setApWpsPin(int ap_index, char *wps_pin);
typedef struct {
	const char *test_name;
	int ap_index;
	int pin_len;                   /* -1: NULL pin; >= 0: heap string of exactly pin_len characters (an over-read aborts under ASan); -2: use pin_text */
	const char *pin_text;
	int callee_ret;                /* what the stubbed wifi_hal_nl80211_wps_pin returns */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call */
	int expected_ret;
} hwr_wpp_case_t;
extern hwr_wpp_case_t sg_wifi_hal_setApWpsPin_suite[];
extern "C" void run_all_tests_sg_wifi_hal_setApWpsPin(void);
#endif
