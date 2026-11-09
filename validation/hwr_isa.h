/* hwr_isa.h - plumbing for the intel wifi_sendActionFrameExt harness (platform/intel) */
#ifndef HWR_ISA_H
#define HWR_ISA_H
#include "hwr_defs.h"
extern "C" INT hwr_int_wifi_sendActionFrameExt(INT apIndex, mac_address_t MacAddr, UINT frequency, UINT wait, UCHAR *frame, UINT len);
typedef struct {
	const char *test_name;
	int ap_index;
	unsigned frequency;
	unsigned wait;
	int frame_mode;                /* 0 NULL, 1 pointer to a fully POISONED runner slab (must not be read), 2 dangling pointer 0xdeadbeef */
	unsigned len;                  /* length passed (not backed by memory: the stub must not read the frame) */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call (the function logs nothing) */
	int expected_ret;
} hwr_isa_case_t;
extern hwr_isa_case_t int_wifi_sendActionFrameExt_suite[];
extern "C" void run_all_tests_int_wifi_sendActionFrameExt(void);
#endif
