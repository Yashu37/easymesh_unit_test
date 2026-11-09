/* hwr_esb.h - plumbing for the wifi-emulator wifi_rrm_send_beacon_req harness (platform/wifi-emulator) */
#ifndef HWR_ESB_H
#define HWR_ESB_H
#include "hwr_defs.h"
typedef unsigned char u8;
typedef unsigned short u16;
struct wifi_interface_info_t;      /* opaque: the stub never touches it */
struct wpa_ssid_value;
extern "C" int hwr_em_wifi_rrm_send_beacon_req(struct wifi_interface_info_t *interface, const u8 *addr,
    u16 num_of_repetitions, u8 measurement_request_mode, u8 oper_class, u8 channel,
    u16 random_interval, u16 measurement_duration, u8 mode, const u8 *bssid,
    struct wpa_ssid_value *ssid, u8 *rep_cond, u8 *rep_cond_threshold, u8 *rep_detail,
    const u8 *ap_ch_rep, unsigned int ap_ch_rep_len, const u8 *req_elem, unsigned int req_elem_len,
    u8 *ch_width, u8 *ch_center_freq0, u8 *ch_center_freq1, u8 last_indication);
typedef struct {
	const char *test_name;
	int ptr_mode;                  /* 0 every pointer argument NULL, 1 every pointer points into a fully POISONED 256-byte slab (must not be read or written), 2 every pointer dangling (0xdeadbeef) */
	unsigned reps;                 /* num_of_repetitions, random_interval, measurement_duration, ap_ch_rep_len, req_elem_len base value */
	unsigned small;                /* value of every u8 argument (mode, oper_class, channel, ..., last_indication) */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call */
	int expected_ret;
} hwr_esb_case_t;
extern hwr_esb_case_t em_wifi_rrm_send_beacon_req_suite[];
extern "C" void run_all_tests_em_wifi_rrm_send_beacon_req(void);
#endif
