#ifndef HWR_GTX_H
#define HWR_GTX_H
#include "hwr_defs.h"
extern "C" INT hwr_wifi_hal_getApAssociatedDeviceTxStatsResult(INT radioIndex, mac_address_t *clientMacAddress, wifi_associated_dev_rate_info_tx_stats_t **stats_array, UINT *output_array_size, ULLONG *handle);   /* renamed, see the handler file */
typedef struct {
	const char *test_name;
	int radio_index; int callee_ret; unsigned n_entries;
	unsigned null_mask;                 /* 1 mac, 2 stats_array, 4 output_array_size, 8 handle passed as NULL; 16 = the platform stub reports a size but returns no array */
	int calls; int check_log;
	int expected_ret; int forked;
} hwr_gtx_case_t;
extern hwr_gtx_case_t wifi_hal_getApAssociatedDeviceTxStatsResult_suite[];
extern "C" void run_all_tests_wifi_hal_getApAssociatedDeviceTxStatsResult(void);
typedef struct { int calls; INT radio; mac_address_t *mac; wifi_associated_dev_rate_info_tx_stats_t **arr; UINT *size; ULLONG *handle; } hwr_gtx_rec_t;
extern hwr_gtx_rec_t hwr_gtx_rec;
void hwr_gtx_configure(int callee_ret, unsigned n_entries, int inconsistent);
#endif
