/* hwr_wss.h - plumbing for the sg_wifi_hal_startScan harness (src/wifi_hal.c).
 * wifi_radio_info_t / wifi_interface_info_t / hash_map_t / g_wifi_hal are minimal STAND-INS with the members the function uses (radio->oper_param, interface_map, rnr_enabled; interface->vap_info,
 * scan_info_mutex, scan_info_map; g_wifi_hal.num_radios / radio_info[]); wifi_radio_operationParam_t, wifi_vap_info_t and ssid_t are the REAL types from the HAL headers.  get_radio_by_rdk_index,
 * the hash-map helpers, the country / op class / channel->frequency helpers and nl80211_start_scan are stubs over runner data. */
#ifndef HWR_WSS_H
#define HWR_WSS_H
#include "hwr_defs.h"
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>
#define HWR_WSS_MAXR 4
#define HWR_WSS_MAXI 4
#define HWR_WSS_MAXS 8
#define HWR_WSS_FREQ_REC 160
typedef struct { void *items[HWR_WSS_MAXS]; int n; int itr; } hash_map_t;
typedef struct wifi_interface_info_t {
	wifi_vap_info_t vap_info;
	pthread_mutex_t scan_info_mutex;
	hash_map_t *scan_info_map;
} wifi_interface_info_t;
typedef struct wifi_radio_info_t {
	wifi_radio_operationParam_t oper_param;
	hash_map_t *interface_map;
	bool rnr_enabled;
} wifi_radio_info_t;
typedef struct { unsigned int num_radios; wifi_radio_info_t radio_info[HWR_WSS_MAXR]; } hwr_wss_hal_t;
typedef struct {
	hwr_wss_hal_t hal;
	wifi_interface_info_t ifs[HWR_WSS_MAXI];
	hash_map_t imaps[HWR_WSS_MAXR];
	hash_map_t smap;
	int no_radio, malloc_fail, start_ret;
	int malloc_calls, free_calls, live_alloc, cleanup_calls, start_calls;
	unsigned last_flags; int last_nfreq, last_dwell, last_nssid; void *last_iface;
	unsigned last_freqs[HWR_WSS_FREQ_REC]; char last_ssid0[33];
	int country_calls;
} hwr_wss_world_t;
extern hwr_wss_world_t hwr_wss_world;
extern "C" int hwr_sg_wifi_hal_startScan(wifi_radio_index_t index, wifi_neighborScanMode_t scan_mode, INT dwell_time, UINT num, UINT *chan_list);
typedef struct {
	const char *test_name;
	int index;
	int scan_mode;                 /* 0 ONCHAN, 1 OFFCHAN, 2 invalid mode */
	int dwell;
	unsigned num;
	int chan_null;                 /* chan_list argument NULL */
	int chan_kind;                 /* 0 all chan_val, 1 alternating chan_val / 0, 2 ascending 1.., 3 all 255 (frequency 0), 4 all 0 (invalid) */
	unsigned chan_val;
	unsigned radio_channel;        /* radio->oper_param.channel (ONCHAN) */
	int no_radio, imap_null;
	int n_if, sta_pos;             /* interfaces on the radio; position of the STA one (-1: none) */
	int malloc_fail;
	int bad_country;               /* countryCode beyond wifi_countrycode_ZW: every op class lookup fails */
	unsigned band6_mask;           /* bit r: radio r is on the 6 GHz band */
	int start_ret;                 /* nl80211_start_scan result */
	int ssid_len;
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wss_case_t;
extern hwr_wss_case_t sg_wifi_hal_startScan_suite[];
extern "C" void run_all_tests_sg_wifi_hal_startScan(void);
#endif
