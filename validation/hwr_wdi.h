/* hwr_wdi.h - plumbing for the sg_wifi_hal_disassoc harness (src/wifi_hal.c).
 * wifi_interface_info_t / struct hostapd_data / g_wifi_hal are minimal STAND-INS with the members the function reads (vap_index for the lookup, u.ap.hapd.own_addr, g_wifi_hal.hapd_lock); the rest of the
 * interface is poisoned padding.  get_interface_by_vap_index is a lookup over the runner's interface list (returns NULL for an unknown vap index like the real one); wifi_drv_sta_disassoc (the
 * non-BANANA_PI_PORT signature, src/wifi_hal_nl80211.c:14138) is a recording stub. */
#ifndef HWR_WDI_H
#define HWR_WDI_H
#include "hwr_defs.h"
#include <pthread.h>
#include <stdint.h>
typedef unsigned char u8;
typedef unsigned short u16;
#define ETH_ALEN 6
#define HWR_WDI_MAXI 4
struct hostapd_data { void *pad_before[2]; u8 own_addr[ETH_ALEN]; u8 pad_after[10]; };
typedef struct wifi_interface_info_t {
	int vap_index;
	char pad1[24];
	union { struct { struct hostapd_data hapd; } ap; struct { int state; char pad[40]; } sta; } u;
	char pad2[16];
} wifi_interface_info_t;
typedef struct { pthread_mutex_t hapd_lock; } hwr_wdi_hal_t;
typedef struct {
	hwr_wdi_hal_t hal;
	wifi_interface_info_t ifs[HWR_WDI_MAXI];     /* vap indexes 0, 1, 5, 14 */
	int vap_ids[HWR_WDI_MAXI];                   /* lookup keys of ifs[] (kept outside the interfaces so they can stay poisoned) */
	int calls; void *call_priv; u8 call_own[ETH_ALEN]; const u8 *call_addr; u16 call_reason; int lock_free_in_call;
} hwr_wdi_world_t;
extern hwr_wdi_world_t hwr_wdi_world;
extern "C" void hwr_sg_wifi_hal_disassoc(int vap_index, int status, uint8_t *mac);
typedef struct {
	const char *test_name;
	int vap_index;                 /* vap index argument (interfaces exist for 0, 1, 5, 14) */
	int status;                    /* status / reason argument */
	int mac_mode;                  /* 0: NULL, 1: runner mac aa:bb:..., 2: all 0xff, 3: all zero */
	int own_kind;                  /* hostapd own_addr of the interface: 0 normal, 1 all 0xff, 2 all zero */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wdi_case_t;
extern hwr_wdi_case_t sg_wifi_hal_disassoc_suite[];
extern "C" void run_all_tests_sg_wifi_hal_disassoc(void);
#endif
