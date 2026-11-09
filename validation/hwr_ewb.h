/* hwr_ewb.h - plumbing for the wifi-emulator wifi_wnm_send_bss_tm_req harness (platform/wifi-emulator) */
#ifndef HWR_EWB_H
#define HWR_EWB_H
#include <stddef.h>
#include "hwr_defs.h"
typedef unsigned char u8;
struct wifi_interface_info_t;      /* opaque: the stub never touches it */
struct sta_info;
extern "C" int hwr_em_wifi_wnm_send_bss_tm_req(struct wifi_interface_info_t *interface, struct sta_info *sta,
    u8 dialog_token, u8 req_mode, int disassoc_timer, u8 valid_int, const u8 *bss_term_dur,
    const char *url, const u8 *nei_rep, size_t nei_rep_len, const u8 *mbo_attrs, size_t mbo_len);
typedef struct {
	const char *test_name;
	int ptr_mode;                  /* 0 every pointer argument NULL, 1 every pointer points into a fully POISONED 256-byte slab (must not be read or written), 2 every pointer dangling (0xdeadbeef) */
	unsigned small;                /* value of every u8 argument (dialog_token, req_mode, valid_int) */
	int timer;                     /* disassoc_timer */
	unsigned long len;             /* nei_rep_len and mbo_len (not backed by memory) */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call */
	int expected_ret;
} hwr_ewb_case_t;
extern hwr_ewb_case_t em_wifi_wnm_send_bss_tm_req_suite[];
extern "C" void run_all_tests_em_wifi_wnm_send_bss_tm_req(void);
#endif
