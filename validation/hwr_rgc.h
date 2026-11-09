/* hwr_rgc.h - plumbing for the raspberry-pi wifi_getRadioChannel harness (platform/raspberry-pi) */
#ifndef HWR_RGC_H
#define HWR_RGC_H
#include "hwr_defs.h"
extern "C" INT hwr_rp_wifi_getRadioChannel(INT radioIndex, ULONG *output_ulong);
typedef struct {
	const char *test_name;
	int radio_index;
	int out_mode;                  /* 0 NULL, 1 the runner's ULONG slot inside a canary slab (the whole slab POISONED: must not be read or written), 2 dangling pointer 0xdeadbeef */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call */
	int expected_ret;
} hwr_rgc_case_t;
extern hwr_rgc_case_t rp_wifi_getRadioChannel_suite[];
extern "C" void run_all_tests_rp_wifi_getRadioChannel(void);
#endif
