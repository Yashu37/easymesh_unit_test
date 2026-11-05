/* hwr_gtp.h - types / plumbing for the wifi_hal_getRadioTransmitPower harness */
#ifndef HWR_GTP_H
#define HWR_GTP_H
#include "hwr_defs.h"
extern "C" INT hwr_gtp_platform(INT radioIndex, ULONG *tx_power);                      /* platform stub (construct file) */
extern "C" INT hwr_wifi_hal_getRadioTransmitPower(INT radioIndex, ULONG *output_ulong);   /* renamed, see the handler file */
typedef struct {
	const char *test_name;
	int radio; int null_out; int callee_ret; unsigned long power;
	int calls; int check_log;
	int expected_ret; int forked;
} hwr_gtp_case_t;
extern hwr_gtp_case_t wifi_hal_getRadioTransmitPower_suite[];
extern "C" void run_all_tests_wifi_hal_getRadioTransmitPower(void);
typedef struct { int calls; int radio; ULONG *out; } hwr_gtp_rec_t;
extern hwr_gtp_rec_t hwr_gtp_rec;
void hwr_gtp_configure(int callee_ret, unsigned long power);
#endif
