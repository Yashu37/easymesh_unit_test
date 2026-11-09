/* hwr_bgp.h - plumbing for the broadcom wifi_getRadioTransmitPower harness (platform/broadcom) */
#ifndef HWR_BGP_H
#define HWR_BGP_H
#include "hwr_defs.h"
extern "C" INT hwr_bcm_wifi_getRadioTransmitPower(INT radioIndex, ULONG *tx_power);
typedef struct {
	int calls, last_radio;
	ULONG *last_tx;
	int ret;                       /* what the stub wifi_hal_getRadioTransmitPower returns */
	ULONG write_value; int write_out;   /* the stub can write a value through the pointer (mode 3 of the case) */
} hwr_bgp_world_t;
extern hwr_bgp_world_t hwr_bgp_world;
typedef struct {
	const char *test_name;
	int radio_index;
	int tx_mode;                   /* 0 NULL, 1 the runner's (poisoned) slot, 2 dangling 0xdeadbeef, 3 runner's slot the core writes 37 into (not poisoned) */
	int core_ret;                  /* return value of wifi_hal_getRadioTransmitPower */
	int calls;
} hwr_bgp_case_t;
extern hwr_bgp_case_t wifi_getRadioTransmitPower_bcm_suite[];
extern "C" void run_all_tests_wifi_getRadioTransmitPower_bcm(void);
#endif
