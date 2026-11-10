/* hwr_whc.h - plumbing for the sg_wifi_hal_connect harness (src/wifi_hal.c).
 * wifi_interface_info_t / hash_map_t are minimal STAND-INS with the members the function uses (vap_info, scan_info_mutex, scan_info_map, u.sta.backhaul); wifi_bss_info_t and wifi_vap_info_t are
 * the REAL types from wifi_hal.h.  The union u overlaps the STA data with an AP blob exactly as the real wifi_interface_info_t does.  nl80211_connect_sta is a recording stub. */
#ifndef HWR_WHC_H
#define HWR_WHC_H
#include "hwr_defs.h"
#include <pthread.h>
#include <stdint.h>
#define HWR_WHC_MAXI 4
#define HWR_WHC_MAXS 5
typedef struct { wifi_bss_info_t *items[HWR_WHC_MAXS]; int n; int itr; } hash_map_t;
typedef struct wifi_interface_info_t {
	wifi_vap_info_t vap_info;
	pthread_mutex_t scan_info_mutex;
	hash_map_t *scan_info_map;
	union {
		struct { wifi_bss_info_t backhaul; } sta;
		struct { uint8_t blob[64]; } ap;            /* the AP side of the union: hostapd data, not a backhaul */
	} u;
} wifi_interface_info_t;
typedef struct {
	unsigned int num_ifs;
	wifi_interface_info_t ifs[HWR_WHC_MAXI];
	hash_map_t maps[HWR_WHC_MAXI];
	wifi_bss_info_t scan[HWR_WHC_MAXI][HWR_WHC_MAXS];
	int connect_calls, connect_ret; wifi_interface_info_t *connect_if;
} hwr_whc_world_t;
extern hwr_whc_world_t hwr_whc_world;
extern "C" int hwr_sg_wifi_hal_connect(int ap_index, wifi_bss_info_t *bss);
typedef struct {
	const char *test_name;
	int vap_index;
	unsigned n_if;                 /* interfaces that exist (vap indexes 0 .. n_if-1) */
	int sta_mask;                  /* bit k: interface k is a STA VAP (the others are AP VAPs) */
	int bss_mode;                  /* 0 NULL, 1 a bss with a non-zero bssid, 2 a bss with an all-zero bssid (use the scan list) */
	unsigned n_scan;               /* scan list entries of every interface */
	unsigned match_mask;           /* bit k: scan entry k has the VAP's SSID */
	int rssi[HWR_WHC_MAXS];        /* rssi of scan entry k */
	int ignite;                    /* the VAP uses its repurposed SSID (the entries carry the other SSID unless ignite_match) */
	int ignite_match;              /* with ignite: the matching entries carry the repurposed SSID */
	int empty_ssid;                /* the VAP's SSID and the matching entries' SSID are empty */
	int connect_ret;
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_whc_case_t;
extern hwr_whc_case_t sg_wifi_hal_connect_suite[];
extern "C" void run_all_tests_sg_wifi_hal_connect(void);
#endif
