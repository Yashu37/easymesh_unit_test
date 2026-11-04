/* hwr_ssid.h - types / plumbing shared by the wifi_hal_getSSIDNumberOfEntries harness files */
#ifndef HWR_SSID_H
#define HWR_SSID_H
#include "hwr_defs.h"
#define HWR_MAX_RADIOS  4
#define HWR_MAX_IFACES  16
#define HWR_PAD_BYTES   128
typedef struct { unsigned int vap_index; wifi_vap_mode_t vap_mode; } hwr_vap_info_t;
typedef struct { hwr_vap_info_t vap_info; } hwr_iface_t;
typedef struct { hwr_iface_t *items[8]; int n; } hwr_hash_map_t;
typedef struct { unsigned int rdk_radio_index; hwr_hash_map_t *interface_map; } hwr_radio_t;
typedef struct { unsigned int num_radios; hwr_radio_t *radio_info; } hwr_g_wifi_hal_t;
extern hwr_g_wifi_hal_t hwr_g_wifi_hal;
extern "C" INT hwr_wifi_hal_getSSIDNumberOfEntries(ULONG *numEntries);   /* wifi_hal_getSSIDNumberOfEntries (renamed, see the handler file) */

typedef struct { unsigned vap_index; int mode; } hwr_if_t;                    /* mode 0 ap, 1 sta, 2 monitor */
typedef struct { unsigned rdk_index; int n; hwr_if_t ifs[8]; } hwr_rd_t;
typedef struct {
	const char *test_name;
	int nradios; hwr_rd_t r[HWR_MAX_RADIOS];
	int null_out; int calls; int preset_garbage; int check_log;
	unsigned long expected; int forked;
} hwr_ssid_case_t;
extern hwr_ssid_case_t wifi_hal_getSSIDNumberOfEntries_suite[];
extern "C" void run_all_tests_wifi_hal_getSSIDNumberOfEntries(void);
#endif
