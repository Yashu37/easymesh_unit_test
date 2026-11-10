/* hwr_wri.h - plumbing for the sg_wifi_hal_rnr_init harness (src/wifi_hal.c).
 * wifi_radio_info_t is a minimal STAND-IN (rnr, rnr_enabled, index) with the REAL rnr_scan_t layout (src/wifi_hal_priv.h:253-263); get_radio_by_rdk_index is a stub over runner data;
 * rnr_crc32 is the real function (wifi_hal_nl80211_utils.c:3043-3053) copied into the handler file. */
#ifndef HWR_WRI_H
#define HWR_WRI_H
#include "hwr_defs.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#define HWR_WRI_MAXR 4
#define RNR_FREQ_CAP 64u
typedef struct {
	uint32_t freq[RNR_FREQ_CAP];
	unsigned int nfreq;
	uint32_t ssid_crc;
	bool have_ssid;
	bool scan_started;
	ssid_t ssid;
} rnr_scan_t;
typedef struct wifi_radio_info_t { unsigned int index; rnr_scan_t rnr; bool rnr_enabled; } wifi_radio_info_t;
typedef struct { wifi_radio_info_t radios[HWR_WRI_MAXR]; int no_radio; } hwr_wri_world_t;
extern hwr_wri_world_t hwr_wri_world;
extern "C" uint32_t hwr_wri_crc32(const uint8_t *p, size_t n);
extern "C" void hwr_sg_wifi_hal_rnr_init(wifi_radio_index_t radio_index, const char *ssid);
typedef struct {
	const char *test_name;
	unsigned radio_index;
	int no_radio;
	int ssid_mode;                 /* 0 NULL, 1 "" , 2 string of ssid_len chars (exact heap block) */
	int ssid_len;
	int dirty;                     /* radio->rnr / rnr_enabled hold old values before the call */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wri_case_t;
extern hwr_wri_case_t sg_wifi_hal_rnr_init_suite[];
extern "C" void run_all_tests_sg_wifi_hal_rnr_init(void);
#endif
