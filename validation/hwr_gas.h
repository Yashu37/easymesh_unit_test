#ifndef HWR_GAS_H
#define HWR_GAS_H
#include "hwr_defs.h"
extern "C" INT hwr_wifi_hal_getApAssociatedDeviceStats(INT apIndex, mac_address_t *clientMacAddress, wifi_associated_dev_stats_t *associated_dev_stats, ULLONG *handle);   /* renamed, see the handler file */
typedef struct {
	const char *test_name;
	int ap_index; int callee_ret; unsigned null_mask;     /* null_mask: 1 mac, 2 stats, 4 handle passed as NULL */
	unsigned long long handle_val; int calls; int check_log;
	int expected_ret; int forked;
} hwr_gas_case_t;
extern hwr_gas_case_t wifi_hal_getApAssociatedDeviceStats_suite[];
extern "C" void run_all_tests_wifi_hal_getApAssociatedDeviceStats(void);
/* recorded by the platform-function stub */
typedef struct { int calls; INT ap_index; mac_address_t *mac; wifi_associated_dev_stats_t *stats; ULLONG *handle; int ret; unsigned long long handle_val; } hwr_gas_rec_t;
extern hwr_gas_rec_t hwr_gas_rec;
#endif
