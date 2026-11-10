/* hwr_wda.h - plumbing for the sg_wifi_hal_deauth harness (src/wifi_hal.c).
 * wifi_interface_info_t / hostapd_data / g_wifi_hal are minimal STAND-INS with the members the function uses (interface->vap_info, interface->u.ap.hapd.own_addr); the vap info
 * type is the REAL one from wifi_hal.h.  The union u overlaps the AP data with a STA blob exactly as the real wifi_interface_info_t does. */
#ifndef HWR_WDA_H
#define HWR_WDA_H
#include "hwr_defs.h"
#include <pthread.h>
#include <stdint.h>
#include <stddef.h>
#define HWR_WDA_MAXI 3
typedef uint8_t u8;
#define ETH_ALEN 6
struct hostapd_data { u8 own_addr[ETH_ALEN]; };
typedef struct wifi_interface_info_t {
	wifi_vap_info_t vap_info;
	union {
		struct { struct hostapd_data hapd; } ap;
		struct { u8 blob[64]; } sta;                 /* the STA side of the union: wpa_supplicant data, not a hostapd_data */
	} u;
} wifi_interface_info_t;
typedef struct { pthread_mutex_t hapd_lock; unsigned int num_ifs; } hwr_wda_hal_t;
typedef struct {
	hwr_wda_hal_t hal;
	wifi_interface_info_t ifs[HWR_WDA_MAXI];
	int deauth_calls; wifi_interface_info_t *d_if; u8 d_own[ETH_ALEN]; const u8 *d_mac; int d_status;
} hwr_wda_world_t;
extern hwr_wda_world_t hwr_wda_world;
extern "C" void hwr_sg_wifi_hal_deauth(int vap_index, int status, uint8_t *mac);
typedef struct {
	const char *test_name;
	int vap_index;
	unsigned n_if;                 /* interfaces that exist (vap indexes 0 .. n_if-1) */
	int sta;                       /* 1: the interface with this vap_index is a STA VAP (its union holds STA data, 0xEE) */
	int mac_mode;                  /* 0 NULL, 1 pointer to a fully POISONED 64-byte runner slab (the wrapper must not touch it), 2 dangling 0xdeadbeef */
	int status;
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wda_case_t;
extern hwr_wda_case_t sg_wifi_hal_deauth_suite[];
extern "C" void run_all_tests_sg_wifi_hal_deauth(void);
#endif
