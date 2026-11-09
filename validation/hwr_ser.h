/* hwr_ser.h - plumbing for the wifi_steering_eventRegister harness (platform/banana-pi) */
#ifndef HWR_SER_H
#define HWR_SER_H
#include "hwr_defs.h"
extern "C" INT hwr_wifi_steering_eventRegister(wifi_steering_eventCB_t event_cb);
typedef struct {
	const char *test_name;
	int cb_mode;                   /* 0 NULL, 1 the runner's counting callback (must never be called), 2 dangling pointer 0xdeadbeef (must never be called) */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call (the function logs nothing: it must stay as it was) */
	int expected_ret;
} hwr_ser_case_t;
extern hwr_ser_case_t wifi_steering_eventRegister_suite[];
extern "C" void run_all_tests_wifi_steering_eventRegister(void);
#endif
