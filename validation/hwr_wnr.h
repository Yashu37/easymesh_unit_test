/* hwr_wnr.h - plumbing for the sg_wifi_hal_setNeighborReports harness (src/wifi_hal.c).
 * wifi_interface_info_t / struct hostapd_data / struct hostapd_bss_config / struct wpabuf are minimal STAND-INS with the members the function uses (interface->vap_info.vap_mode, interface->u.ap.hapd,
 * hapd->conf->iface / radio_measurements[]); wifi_NeighborReport_t, bssid_t and ssid_t are the REAL types from the HAL headers.  The wpabuf is an exact-size heap block (like wpabuf_alloc), so an
 * over-long write is a heap-buffer-overflow.  hostapd_free_neighbor_db / hostapd_neighbor_set and the interface lookup are recording stubs over runner data. */
#ifndef HWR_WNR_H
#define HWR_WNR_H
#include "hwr_defs.h"
#include <pthread.h>
#include <stdint.h>
#include <stddef.h>
#define HWR_WNR_MAXI 4
#define HWR_WNR_MAXSET 12
#define HWR_WNR_NRCAP 320
#define WLAN_RRM_CAPS_NEIGHBOR_REPORT 0x02
#define SSID_MAX_LEN 32
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
struct wpa_ssid_value { u8 ssid[SSID_MAX_LEN]; size_t ssid_len; };
struct wpabuf { size_t size, used; u8 *buf; };
struct hostapd_bss_config { char iface[16]; u8 radio_measurements[5]; };
struct hostapd_data { struct hostapd_bss_config *conf; };
typedef struct wifi_interface_info_t {
	wifi_vap_info_t vap_info;
	union { struct { struct hostapd_data hapd; } ap; struct { int state; } sta; } u;
} wifi_interface_info_t;
typedef struct { pthread_mutex_t hapd_lock; } hwr_wnr_hal_t;
typedef struct {
	hwr_wnr_hal_t hal;
	wifi_interface_info_t ifs[HWR_WNR_MAXI];
	struct hostapd_bss_config conf;
	int conf_null, set_fail_at, alloc_fail_at;
	int free_calls, set_calls, alloc_calls, live_bufs;
	u8 set_bssid[HWR_WNR_MAXSET][6]; size_t set_ssid_len[HWR_WNR_MAXSET]; u8 set_ssid[HWR_WNR_MAXSET][33]; size_t set_nr_len[HWR_WNR_MAXSET]; u8 set_nr[HWR_WNR_MAXSET][HWR_WNR_NRCAP];
	int mutex_held_at_set;
} hwr_wnr_world_t;
extern hwr_wnr_world_t hwr_wnr_world;
extern "C" int hwr_sg_wifi_hal_setNeighborReports(UINT apIndex, UINT numNeighborReports, wifi_NeighborReport_t *neighborReports);
/* optional sub-element flags (one bit each, all reports of a call carry the same set) */
#define F_WIDE   (1 << 0)
#define F_TSF    (1 << 1)
#define F_CC     (1 << 2)
#define F_PREF   (1 << 3)
#define F_TERM   (1 << 4)
#define F_BEAR   (1 << 5)
#define F_HTC    (1 << 6)
#define F_HTO    (1 << 7)
#define F_VHTC   (1 << 8)
#define F_VHTO   (1 << 9)
#define F_SEC    (1 << 10)
#define F_RM     (1 << 11)
#define F_VEND   (1 << 12)
#define F_PILOT  (1 << 13)
#define F_ALL    0x3FFF
typedef struct {
	const char *test_name;
	unsigned apIndex;
	int nrep_null;
	unsigned num;
	int vap_sta, no_iface;
	int conf_null;                 /* hapd->conf is NULL (hostapd not initialised for the VAP) */
	int rm_enable;                 /* radio_measurements[0] has the neighbour report bit */
	unsigned flags;
	int ssid_kind;                 /* 0 "ssid", 1 32 non-NUL chars, 2 empty */
	int set_fail_at;               /* hostapd_neighbor_set fails at this call (1-based, 0 never) */
	int alloc_fail_at;             /* wpabuf_alloc fails at this call (1-based, 0 never) */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wnr_case_t;
extern hwr_wnr_case_t sg_wifi_hal_setNeighborReports_suite[];
extern "C" void run_all_tests_sg_wifi_hal_setNeighborReports(void);
#endif
