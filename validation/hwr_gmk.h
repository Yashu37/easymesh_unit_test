#ifndef HWR_GMK_H
#define HWR_GMK_H
#include "hwr_defs.h"
extern "C" INT hwr_wifi_hal_getMultiPskClientKey(INT apIndex, mac_address_t mac, wifi_key_multi_psk_t *key);   /* renamed, see the handler file */
typedef struct {
	const char *test_name;
	int ap_index; unsigned char mac[6]; unsigned null_mask;     /* null_mask: 1 mac, 2 key passed as NULL */
	int calls; int check_log;
} hwr_gmk_case_t;
extern hwr_gmk_case_t wifi_hal_getMultiPskClientKey_suite[];
extern "C" void run_all_tests_wifi_hal_getMultiPskClientKey(void);
#endif
