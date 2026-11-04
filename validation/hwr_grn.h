#ifndef HWR_GRN_H
#define HWR_GRN_H
#include "hwr_defs.h"
typedef struct { unsigned int num_radios; } hwr_grn_world_t;
extern hwr_grn_world_t hwr_grn_world;
extern "C" INT hwr_wifi_hal_getRadioNumberOfEntries(ULONG *output);   /* renamed, see the handler file */
typedef struct {
	const char *test_name;
	unsigned num_radios; int null_out; int calls; int check_log; int preset;   /* preset: 0 = output preset 0, 1 = 0xA5 pattern */
	int expected_ret; unsigned long expected_out; int forked;                  /* expected_out ignored when the call must fail */
} hwr_grn_case_t;
extern hwr_grn_case_t wifi_hal_getRadioNumberOfEntries_suite[];
extern "C" void run_all_tests_wifi_hal_getRadioNumberOfEntries(void);
#endif
