/* hwr_wbt.h - plumbing for the sg_wifi_hal_setBTMRequest harness (src/wifi_hal.c).
 * wifi_interface_info_t / struct sta_info / struct hostapd_data are minimal STAND-INS with the members the function uses (interface->vap_info.vap_mode, interface->u.ap.hapd); wifi_BTMRequest_t,
 * wifi_NeighborReport_t and mac_address_t are the REAL types from the HAL headers.  get_interface_by_vap_index, ap_get_sta and wifi_wnm_send_bss_tm_req are recording stubs over runner data. */
#ifndef HWR_WBT_H
#define HWR_WBT_H
#include "hwr_defs.h"
#include <pthread.h>
#include <stdint.h>
#define HWR_WBT_MAXI 4
#define HWR_WBT_NEI_MAX 2048
typedef uint8_t u8;
struct hostapd_data { int dummy; };
struct sta_info { int tag; };
typedef struct wifi_interface_info_t {
	wifi_vap_info_t vap_info;
	union { struct { struct hostapd_data hapd; } ap; struct { int state; } sta; } u;
} wifi_interface_info_t;
typedef struct { pthread_mutex_t hapd_lock; } hwr_wbt_hal_t;
typedef struct {
	hwr_wbt_hal_t hal;
	wifi_interface_info_t ifs[HWR_WBT_MAXI];
	struct sta_info sta;
	unsigned char known_mac[6];
	int no_sta, malloc_fail_at, malloc_calls, live_alloc, send_ret;
	int send_calls; void *send_sta; unsigned send_token, send_mode; int send_timer; unsigned send_valid;
	u8 send_term[12]; int send_url_null; char send_url[1100]; int send_nei_null, send_nei_len; u8 send_nei[HWR_WBT_NEI_MAX];
	int mutex_held_at_send;
} hwr_wbt_world_t;
extern hwr_wbt_world_t hwr_wbt_world;
extern "C" int hwr_sg_wifi_hal_setBTMRequest(UINT apIndex, mac_address_t peerMac, wifi_BTMRequest_t *request);
typedef struct {
	const char *test_name;
	unsigned apIndex;
	int peer_null, req_null;
	int no_iface, vap_sta, no_sta;
	unsigned mode;                 /* request->requestMode: bit0 candidates, bit3 termination, bit4 ESS disassoc */
	unsigned dur;                  /* termDuration.duration (tsf is set to a pattern) */
	unsigned ncand;                /* numCandidates */
	unsigned urlLen;
	int url_kind;                  /* 0 'u' x min(urlLen,511), 1 url[0] = 0, 2 the whole request struct filled with 'A' (no NUL anywhere) */
	unsigned token;
	int malloc_fail_at;            /* 1: first malloc fails (candidates), 2: second (url), 0 none */
	int send_ret;                  /* wifi_wnm_send_bss_tm_req result */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wbt_case_t;
extern hwr_wbt_case_t sg_wifi_hal_setBTMRequest_suite[];
extern "C" void run_all_tests_sg_wifi_hal_setBTMRequest(void);
#endif
