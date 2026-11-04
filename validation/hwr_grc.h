#ifndef HWR_GRC_H
#define HWR_GRC_H
#include "hwr_defs.h"
extern "C" INT hwr_wifi_hal_getRadioChannelStats(INT radioIndex, wifi_channelStats_t *input_output_channelStats_array, INT array_size);   /* renamed, see the handler file */
typedef struct {
	const char *test_name;
	int radio_index; int array_size; int callee_ret; int null_arr;
	int calls; int check_log;
	int expected_ret;
	int expected_fwd;         /* array_size the platform function must receive; -1 = must not be called */
	int forked;
} hwr_grc_case_t;
extern hwr_grc_case_t wifi_hal_getRadioChannelStats_suite[];
extern "C" void run_all_tests_wifi_hal_getRadioChannelStats(void);
typedef struct { int calls; INT radio; wifi_channelStats_t *arr; INT size; } hwr_grc_rec_t;
extern hwr_grc_rec_t hwr_grc_rec;
void hwr_grc_configure(int callee_ret);
#endif
