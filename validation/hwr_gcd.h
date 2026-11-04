#ifndef HWR_GCD_H
#define HWR_GCD_H
#include "hwr_defs.h"
extern "C" INT hwr_wifi_hal_getApAssociatedClientDiagnosticResult(INT apIndex, char *mac_addr, wifi_associated_dev3_t *dev_conn);   /* renamed, see the handler file */
typedef struct {
	const char *test_name;
	int ap_index; int callee_ret; unsigned null_mask;     /* null_mask: 1 mac_addr, 2 dev_conn passed as NULL */
	int calls; int check_log;
	int expected_ret; int forked;
} hwr_gcd_case_t;
extern hwr_gcd_case_t wifi_hal_getApAssociatedClientDiagnosticResult_suite[];
extern "C" void run_all_tests_wifi_hal_getApAssociatedClientDiagnosticResult(void);
typedef struct { int calls; INT ap_index; char *mac; wifi_associated_dev3_t *dev; } hwr_gcd_rec_t;
extern hwr_gcd_rec_t hwr_gcd_rec;
void hwr_gcd_configure(int callee_ret);
#endif
