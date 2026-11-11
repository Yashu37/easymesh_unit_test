/* hwr_wrb.h - plumbing for the sg_wifi_hal_setRMBeaconRequest harness (src/wifi_hal.c).
 * wifi_interface_info_t is a minimal STAND-IN with the members the function uses (interface->vap_info.vap_mode); wifi_BeaconRequest_t and mac_address_t are the REAL types from the HAL headers.
 * get_interface_by_vap_index, ieee80211_chan_to_freq and wifi_rrm_send_beacon_req are recording stubs over runner data. */
#ifndef HWR_WRB_H
#define HWR_WRB_H
#include "hwr_defs.h"
#include <pthread.h>
#include <stdint.h>
#define HWR_WRB_MAXI 4
typedef uint8_t u8;
typedef uint16_t u16;
struct wpa_ssid_value { u8 ssid[32]; size_t ssid_len; };
typedef struct wifi_interface_info_t { wifi_vap_info_t vap_info; } wifi_interface_info_t;
typedef struct { pthread_mutex_t hapd_lock; } hwr_wrb_hal_t;
typedef struct {
	hwr_wrb_hal_t hal;
	wifi_interface_info_t ifs[HWR_WRB_MAXI];
	int send_ret, send_calls, mutex_held_at_send, freq_calls, freq_null_country;
	void *send_iface; const u8 *send_addr; u16 send_nrep, send_rand, send_dur; u8 send_req_mode, send_oc, send_ch, send_mode, send_bssid[6], send_last;
	int ssid_null; size_t ssid_len; u8 ssid_val[33];
	int cond_null, thr_null, det_null; u8 cond, thr, det;
	int chrep_null; unsigned chrep_len; u8 chrep[64]; const u8 *chrep_ptr;
	int elem_null; unsigned elem_len; const u8 *elem_ptr;
	int w_null, c0_null, c1_null; u8 w, c0, c1;
} hwr_wrb_world_t;
extern hwr_wrb_world_t hwr_wrb_world;
extern "C" int hwr_sg_wifi_hal_setRMBeaconRequest(UINT apIndex, mac_address_t peer_mac, wifi_BeaconRequest_t *in_req, UCHAR *out_DialogToken);
typedef struct {
	const char *test_name;
	unsigned apIndex;
	int peer_null, req_null, out_null;
	int no_iface, vap_sta;
	unsigned opClass, channel, mode;
	int ssid_kind;                 /* -1 not present, 0 "abc", 1 32 non-NUL chars, 2 empty */
	int rep_present, det_present;
	int chrep_n;                   /* -1 not present, else number of non-zero channels (0..64; below 64 they are zero-terminated) */
	int elem_present;
	int wide_present; unsigned wide_bw, seg0, seg1;
	int send_ret;                  /* wifi_rrm_send_beacon_req result */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wrb_case_t;
extern hwr_wrb_case_t sg_wifi_hal_setRMBeaconRequest_suite[];
extern "C" void run_all_tests_sg_wifi_hal_setRMBeaconRequest(void);
#endif
