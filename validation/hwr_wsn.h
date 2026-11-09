/* hwr_wsn.h - plumbing for the wifi_startNeighborScan harness (platform/banana-pi -> src/wifi_hal.c wifi_hal_startNeighborScan) */
#ifndef HWR_WSN_H
#define HWR_WSN_H
#include "hwr_defs.h"

/* reduced stand-ins for the hostapd / wifi_hal_priv.h types the function touches (src/wifi_hal_priv.h, hostapd ap_drv_ops) */
typedef struct { unsigned int *values; unsigned int num; } wsn_uint_array_t;            /* uint_array_t, wifi_hal_priv.h:461 */
typedef struct { int chan; int freq; unsigned int flag; } wsn_chan_t;                    /* hostapd_channel_data */
typedef struct { int num_channels; wsn_chan_t *channels; } wsn_hw_mode_t;                /* hostapd_hw_modes */
typedef struct { wsn_hw_mode_t *current_mode; } wsn_hiface_t;                            /* hostapd_iface */
typedef struct { wsn_hiface_t *iface; } wsn_hapd_t;                                      /* hostapd_data */
#define WSN_CHAN_DISABLED 0x1u                                                           /* HOSTAPD_CHAN_DISABLED */

typedef struct {
    int           countryCode;
    unsigned char operatingClass;
    unsigned char channel;
} wsn_oper_param_t;
typedef struct { char name[16]; wsn_oper_param_t oper_param; } wsn_radio_t;

typedef struct {
    unsigned int radio_index;
    int          vap_mode;                  /* wifi_vap_mode_ap / wifi_vap_mode_sta */
    union { struct { char ssid[33]; } sta_info; } u;
} wsn_vap_info_t;
typedef struct {
    char             name[16];
    wsn_vap_info_t   vap_info;
    int              scan_state;
    unsigned int     scan_has_results;
    wsn_uint_array_t scan_filter;
    pthread_mutex_t  scan_state_mutex, scan_info_mutex, scan_info_ap_mutex;
    void            *scan_info_map, *scan_info_ap_map[2];
    union { struct { wsn_hapd_t hapd; } ap; } u;
} wsn_interface_t;

/* the world, owned by the runner */
typedef struct {
    wsn_interface_t *ap_iface;      unsigned int ap_vap_index;     /* interface returned for that ap index (NULL = none) */
    wsn_radio_t     *radio;         unsigned int radio_index;      /* radio returned for that index (NULL = none) */
    wsn_interface_t *priv_iface;                                   /* get_private_vap_interface() result */
    int              nl_start_rc, nl_results_rc;                   /* what the nl80211 stubs return */
    /* recorded by the nl80211 stubs / hash_map_cleanup stub */
    int              start_calls, results_calls, cleanup_calls;
    int              start_flags, start_active, start_dwell;
    unsigned int     start_num, start_values[16];
    char             start_ssid[34];
    int              state_at_results;                             /* scan_state when nl80211_get_scan_results() ran */
} wsn_world_t;
extern wsn_world_t hwr_wsn_world;

extern "C" int wifi_startNeighborScan(INT apIndex, wifi_neighborScanMode_t scan_mode, INT dwell_time, UINT chan_num, UINT *chan_list);
extern "C" void hwr_wsn_cleanup_filter(wsn_interface_t *interface);

#define WSN_MAXL 6
typedef struct {
    const char *test_name;
    /* call arguments */
    int ap_index, mode, dwell; unsigned int chan_num; int list_null; unsigned int list[WSN_MAXL];
    /* world */
    int vap_mode;                 /* 0 = ap, 1 = sta (the vap addressed by ap_index)   */
    int has_ap_iface, has_radio, has_priv;
    unsigned int radio_channel; int country; unsigned int op_class;
    int hapd_state;               /* 0 = hapd.iface NULL, 1 = iface without current_mode, 2 = iface with the channel table */
    int pre_state, pre_results;
    int nl_start_rc, nl_results_rc;
    /* expectations */
    int expected_ret, exp_state;
    int exp_start_calls, exp_results_calls, exp_cleanup;
    unsigned int exp_num; unsigned int exp_vals[WSN_MAXL];   /* scan filter (== values handed to nl80211_start_scan / present at get_scan_results) */
    int exp_flags, exp_active;    /* checked when exp_start_calls */
    int forked;
} hwr_wsn_case_t;
extern hwr_wsn_case_t wifi_startNeighborScan_suite[];
extern "C" void run_all_tests_wifi_startNeighborScan(void);
#endif
