#ifndef HWR_SETRADIOSTATSENABLE_H
#define HWR_SETRADIOSTATSENABLE_H
#include "hwr_defs.h"
typedef struct { const char *test_name; int radio_index; int enabled; int calls; int check; } hwr_srse_case_t;   /* check: 0 none, 1 alternate enabled each call, 2 log text, 3 notice text */
extern hwr_srse_case_t wifi_hal_setRadioStatsEnable_suite[];
extern "C" INT hwr_wifi_hal_setRadioStatsEnable(INT radioIndex, BOOL enabled);   /* wifi_hal_setRadioStatsEnable (renamed, see the handler file) */
extern "C" void run_all_tests_wifi_hal_setRadioStatsEnable(void);
#endif
