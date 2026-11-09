/* hwr_igc.h - plumbing for the intel wifi_getRadioChannel harness (platform/intel) */
#ifndef HWR_IGC_H
#define HWR_IGC_H
#include "hwr_defs.h"
/* stand-in for wifi_radio_info_t: only the members the function reads (configured, oper_param.enable / .channel with the real wifi_radio_operationParam_t) */
typedef struct { int rdk_index; bool configured; wifi_radio_operationParam_t oper_param; } igc_radio_t;
typedef struct { igc_radio_t *radio; int radio_rdk_index; int lookups; int last_lookup; } hwr_igc_world_t;   /* radio_rdk_index: copy of the index the lookup answers to (kept outside the radio object) */
extern hwr_igc_world_t hwr_igc_world;
extern "C" INT hwr_int_wifi_getRadioChannel(INT radioIndex, ULONG *output_ulong);
typedef struct {
	const char *test_name;
	int radio_index;
	int has_radio;                 /* 0 no radio, 1 radio for radio_index, 2 only a radio with another index */
	int configured;
	int enable;                    /* BOOL value (any non-zero value is true) */
	unsigned channel;              /* oper_param.channel */
	int out_mode;                  /* 0 output NULL, 1 the runner's ULONG slot inside a canary slab (head and tail POISONED during the call) */
	int calls;
	int expected_ret;
	int last;                      /* 1: invalid-input row that crashes the original, run last */
} hwr_igc_case_t;
extern hwr_igc_case_t int_wifi_getRadioChannel_suite[];
extern "C" void run_all_tests_int_wifi_getRadioChannel(void);
#endif
