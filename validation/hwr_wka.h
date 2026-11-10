/* hwr_wka.h - plumbing for the sg_wifi_hal_kickAssociatedDevice harness (src/wifi_hal.c).
 * wifi_interface_info_t / hostapd_data / sta_info / g_wifi_hal are minimal STAND-INS with the members the function uses (vap_info, u.ap.hapd.own_addr / sta_list, sta_info.addr / next, the hapd lock);
 * the vap info type is the REAL one from wifi_hal.h.  The union u overlaps the AP data with a STA blob exactly as the real wifi_interface_info_t does.  wifi_drv_sta_disassoc is a recording stub. */
#ifndef HWR_WKA_H
#define HWR_WKA_H
#include "hwr_defs.h"
#include <pthread.h>
#include <stdint.h>
#include <stddef.h>
#define HWR_WKA_MAXI 4
#define HWR_WKA_MAXN 8
#define HWR_WKA_MAXC 64
typedef uint8_t u8;
#define ETH_ALEN 6
#define WLAN_REASON_UNSPECIFIED 1
struct sta_info { struct sta_info *next; u8 addr[ETH_ALEN]; };
struct hostapd_data { u8 own_addr[ETH_ALEN]; struct sta_info *sta_list; };
typedef struct wifi_interface_info_t {
	wifi_vap_info_t vap_info;
	union {
		struct { struct hostapd_data hapd; } ap;
		struct { u8 blob[64]; } sta;                 /* the STA side of the union: wpa_supplicant data, not a hostapd_data */
	} u;
} wifi_interface_info_t;
typedef struct { pthread_mutex_t hapd_lock; unsigned int num_ifs; } hwr_wka_hal_t;
typedef struct { wifi_interface_info_t *intf; u8 own[ETH_ALEN]; u8 addr[ETH_ALEN]; int reason; } hwr_wka_call_t;
typedef struct {
	hwr_wka_hal_t hal;
	wifi_interface_info_t ifs[HWR_WKA_MAXI];
	struct sta_info nodes[HWR_WKA_MAXI][HWR_WKA_MAXN];
	hwr_wka_call_t calls[HWR_WKA_MAXC]; int ncalls;
} hwr_wka_world_t;
extern hwr_wka_world_t hwr_wka_world;
extern "C" int hwr_sg_wifi_hal_kickAssociatedDevice(int ap_index, unsigned char *mac);
typedef struct {
	const char *test_name;
	int vap_index;
	unsigned n_if;                 /* interfaces that exist (vap indexes 0 .. n_if-1) */
	int sta_mask;                  /* bit k: interface k is a STA VAP (the others are AP VAPs) */
	unsigned n_sta;                /* stations in the list of every AP interface (0: sta_list NULL) */
	int mac_mode;                  /* 0 NULL, 1 broadcast, 2 unicast = first station of the list, 3 unicast not in the list, 4 all zero, 5 ff:ff:ff:ff:ff:fe, 6 the interface's own address */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wka_case_t;
extern hwr_wka_case_t sg_wifi_hal_kickAssociatedDevice_suite[];
extern "C" void run_all_tests_sg_wifi_hal_kickAssociatedDevice(void);
#endif
