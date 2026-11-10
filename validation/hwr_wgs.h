/* hwr_wgs.h - plumbing for the sg_wifi_hal_getScanResults harness (src/wifi_hal.c).
 * wifi_radio_info_t / wifi_interface_info_t / hash_map_t are minimal STAND-INS with the members the function uses (radio->oper_param, radio->interface_map, interface->vap_info.vap_mode,
 * interface->scan_info_mutex / scan_info_map); wifi_radio_operationParam_t, wifi_vap_info_t, wifi_bss_info_t and wifi_channel_t are the REAL types from the HAL headers.  The lookup, hash-map,
 * country and channel->frequency helpers are stubs over runner data. */
#ifndef HWR_WGS_H
#define HWR_WGS_H
#include "hwr_defs.h"
#include <pthread.h>
#include <stdint.h>
#define HWR_WGS_MAXR 4
#define HWR_WGS_MAXI 4
#define HWR_WGS_MAXS 12
typedef struct { void *items[HWR_WGS_MAXS]; int n; int itr; } hash_map_t;
typedef struct wifi_interface_info_t {
	wifi_vap_info_t vap_info;
	pthread_mutex_t scan_info_mutex;
	hash_map_t *scan_info_map;
} wifi_interface_info_t;
typedef struct wifi_radio_info_t {
	wifi_radio_operationParam_t oper_param;
	hash_map_t *interface_map;
} wifi_radio_info_t;
typedef struct {
	wifi_radio_info_t radios[HWR_WGS_MAXR];
	wifi_interface_info_t ifs[HWR_WGS_MAXI];
	hash_map_t imaps[HWR_WGS_MAXR];
	hash_map_t smap;
	wifi_bss_info_t scan[HWR_WGS_MAXS];
	int no_radio, calloc_fail, calloc_calls;
	char last_country[8]; int country_calls, freq_calls;
} hwr_wgs_world_t;
extern hwr_wgs_world_t hwr_wgs_world;
extern "C" int hwr_sg_wifi_hal_getScanResults(wifi_radio_index_t index, wifi_channel_t *channel, wifi_bss_info_t **bss, UINT *num_bss);
typedef struct {
	const char *test_name;
	unsigned index;
	int null_channel, null_bss, null_num;
	int no_radio, imap_null;
	int n_if;                      /* interfaces on the radio (ap, ... ) */
	int sta_pos;                   /* index of the STA interface among them (-1: none) */
	int band_mismatch;             /* channel->band differs from the radio band */
	int ch_num;                    /* channel number: 0 -> the frequency lookup fails, 255 -> frequency 0 (no filter), else a normal channel */
	int country;                   /* 0 US, 1 CA, 2 an unknown code (stand-in table falls back to "US") */
	int n_scan;                    /* scan entries of the STA interface */
	unsigned match_mask;           /* bit k: scan entry k is on the requested frequency */
	unsigned zero_mask;            /* bit k: scan entry k has freq 0 (and does not match) */
	int calloc_fail;
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wgs_case_t;
extern hwr_wgs_case_t sg_wifi_hal_getScanResults_suite[];
extern "C" void run_all_tests_sg_wifi_hal_getScanResults(void);
#endif
