/* hwr_gad.h - plumbing for the wifi_getApAssociatedDeviceDiagnosticResult3 harness (platform/banana-pi) */
#ifndef HWR_GAD_H
#define HWR_GAD_H
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/attr.h>
#include <linux/nl80211.h>
#include "hso_hal_ipc.h"
#ifdef __cplusplus
#include "hwr_defs.h"
#else
void hwr_print(int level, const char *format, ...);
#endif

#define GAD_MAXS 8
typedef struct { unsigned char mac[6]; int tmpl; } gad_sta_t;       /* a station the "kernel" knows: its MAC and the statistics template of its reply */
typedef struct { unsigned int vap_index; unsigned int index; unsigned int phy_index; } gad_interface_t;

typedef struct {
    gad_interface_t *iface;                      /* interface returned for iface->vap_index (NULL = none) */
    int              list_cmd_fail, stats_cmd_fail;   /* nl80211_drv_cmd_msg() returns NULL for the station dump / for a station query */
    int              dump_rc;                    /* nl80211_send_and_recv() result of the station dump (the handler has seen the stations first) */
    int              stats_fail_idx;             /* station whose GET_STATION query fails (-1 none) */
    int              fail_calloc;                /* calloc returns NULL */
    int              fail_realloc_at;            /* the n-th realloc (1-based) returns NULL, 0 = never */
    int              quirk;                      /* 0 none, 1 dump: station 0 MAC attribute is 2 bytes, 2 dump: station 0 has no MAC attribute,
                                                     3 (unused) */
    int              nsta; gad_sta_t sta[GAD_MAXS];
    int              calloc_calls, realloc_calls, cmd_calls, send_calls, live;    /* live = blocks allocated through calloc / realloc and not freed */
} gad_world_t;
extern gad_world_t hwr_gad_world;

/* statistics carried by the GET_STATION reply of one station, and what the diagnostic entry must contain */
typedef struct {
    unsigned rx_bytes, tx_bytes, rx_pkts, tx_pkts, tx_failed, retries;
    unsigned long long rx_drop;
    int signal;                                   /* NL80211_STA_INFO_SIGNAL, 0 = attribute absent */
    unsigned tx_br32; int tx_kind;                /* TX bitrate: BITRATE32 (0 = absent) and the standard flag: 0 none 1 HE 2 VHT 3 MCS 4 only the bitrate */
    unsigned rx_br32; int rx_kind;                /* RX bitrate, same encoding */
    int flags_mode;                               /* STA_FLAGS: 0 absent, 1 authorized, 2 flags present but not authorized */
    int empty_info;                               /* 1: STA_INFO nest has no attributes at all */
    /* expected */
    const char *e_std; unsigned e_down, e_up; int e_auth;
} gad_tmpl_t;
#define GAD_NTMPL 8
extern gad_tmpl_t gad_tmpl[GAD_NTMPL];

#ifdef __cplusplus
extern "C" {
#endif
INT hwr_wifi_getApAssociatedDeviceDiagnosticResult3(INT apIndex, wifi_associated_dev3_t **associated_dev_array, UINT *output_array_size);
#ifdef __cplusplus
}
#endif

/* name, ap_index, has_iface, args (1 array ptr NULL, 2 size ptr NULL, 3 both), nsta, tmpl[], list_cmd_fail, stats_cmd_fail, dump_rc, stats_fail_idx,
 * fail_calloc, fail_realloc_at, quirk, calls, expected_ret, exp_size (-1 = nsta), exp_untouched, exp_null_out (outputs NULL, 0), last */
typedef struct {
    const char *test_name;
    int ap_index, has_iface, args;
    int nsta; int tmpl[GAD_MAXS];
    int list_cmd_fail, stats_cmd_fail, dump_rc, stats_fail_idx, fail_calloc, fail_realloc_at, quirk;
    int calls, expected_ret, exp_size, exp_untouched, exp_null_out, last;
} gad_case_t;
extern gad_case_t wifi_getApAssociatedDeviceDiagnosticResult3_suite[];
#ifdef __cplusplus
extern "C" void run_all_tests_wifi_getApAssociatedDeviceDiagnosticResult3(void);
#endif
#endif
