/* hwr_gnw.h - plumbing for the wifi_getNeighboringWiFiStatus harness (platform/banana-pi -> src/wifi_hal.c _wifi_hal_getNeighboringWiFiStatus) */
#ifndef HWR_GNW_H
#define HWR_GNW_H
#include <pthread.h>
#include "hwr_defs.h"

#define GNW_MAXB 8

/* stand-in for hash_map_t (the scan result map holds wifi_bss_info_t pointers, collection.c walks them in insertion order) */
typedef struct { wifi_bss_info_t *items[GNW_MAXB]; int n; } gnw_map_t;

typedef struct { unsigned int *values; unsigned int num; } gnw_uint_array_t;            /* uint_array_t, wifi_hal_priv.h:461 */
typedef struct { char name[16]; } gnw_radio_t;
typedef struct {
    char             name[16];
    int              scan_state;
    unsigned int     scan_has_results;
    gnw_uint_array_t scan_filter;
    pthread_mutex_t  scan_state_mutex, scan_info_mutex, scan_info_ap_mutex;
    gnw_map_t       *scan_info_ap_map[2];
} gnw_interface_t;

typedef struct {
    gnw_radio_t     *radio;  unsigned int radio_index;       /* radio returned for that index (NULL = none) */
    gnw_interface_t *priv_iface;                              /* get_private_vap_interface() result */
    int              fail_calloc, fail_realloc;               /* make the allocation fail */
    int              calloc_calls, realloc_calls;
} gnw_world_t;
extern gnw_world_t hwr_gnw_world;

extern "C" int hwr_wifi_getNeighboringWiFiStatus(INT radio_index, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *output_array_size);

/* canned scan results: the raw input and what the decoded wifi_neighbor_ap2_t must contain */
typedef struct {
    const char *ssid; unsigned char bssid[6]; unsigned short caps; unsigned int freq; int rssi;
    int sec_mode, enc_method, band; int supp_std, oper_std, bw, basic, supp_rates;
    unsigned beacon, dtim, util; int noise; int load; unsigned sta;
    /* expected */
    const char *e_mode, *e_bssid, *e_sec, *e_enc, *e_band, *e_supp_std, *e_oper_std, *e_bw, *e_basic, *e_supp_rates;
    unsigned e_channel;
} gnw_tmpl_t;
#define GNW_NTMPL 8
extern gnw_tmpl_t gnw_tmpl[GNW_NTMPL];

/* name, radio_index (100 = MAX_NUM_RADIOS, 101 = MAX_NUM_RADIOS-1), args (1 = array ptr NULL, 2 = size ptr NULL, 3 = both),
 * has_radio, has_priv, pre_state (0 NONE 1 ERROR 2 STARTED 3 ABORTED), pre_results, nbss, bss[] (template ids), nfilt, filt[], fail_calloc, fail_realloc,
 * calls, expected_ret, expected_ret2, exp_state, exp_results, exp_again, exp_untouched */
typedef struct {
    const char *test_name;
    int radio_index, args, has_radio, has_priv, pre_state, pre_results;
    int nbss; int bss[GNW_MAXB];
    int nfilt; unsigned filt[3];
    int fail_calloc, fail_realloc;
    int calls, expected_ret, expected_ret2;
    int exp_state, exp_results, exp_again, exp_untouched;
} gnw_case_t;
extern gnw_case_t wifi_getNeighboringWiFiStatus_suite[];

extern gnw_map_t gnw_map0, gnw_map1;
extern wifi_bss_info_t gnw_store[GNW_MAXB];
extern unsigned int gnw_filt_slab[8];
extern gnw_interface_t gnw_iface;
extern gnw_radio_t gnw_radio;
int gnw_resolve_index(int idx);
gnw_interface_t *construct_wifi_getNeighboringWiFiStatus_input(const gnw_case_t *t);

extern "C" void run_all_tests_wifi_getNeighboringWiFiStatus(void);
#endif
