/* hwr_bga.h - plumbing for the broadcom wifi_getApAssociatedDeviceDiagnosticResult3 harness (platform/broadcom) */
#ifndef HWR_BGA_H
#define HWR_BGA_H
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

#define BGA_MAXS 8
typedef struct { unsigned int vap_index; unsigned int index; unsigned int phy_index; } bga_interface_t;

/* the "kernel": the stations it knows and what its replies look like */
typedef struct {
    bga_interface_t *iface;
    int list_cmd_fail, stats_cmd_fail;        /* nl80211_drv_vendor_cmd_msg returns NULL for the station-list / station-stats command */
    int dump_rc, stats_rc, stats_fail_idx;    /* nl80211_send_and_recv result of the list command / of the stats commands (stats_fail_idx = station that fails, -1 none) */
    int fail_calloc;                          /* every calloc of the function returns NULL */
    unsigned long calloc_limit;               /* a calloc of more bytes than this returns NULL (models out-of-memory), 0 = no limit */
    int nsta; unsigned char mac[BGA_MAXS][6];
    long long sta_num;                        /* value of RDK_VENDOR_ATTR_STA_NUM in the list reply (-1 = nsta) */
    int list_entries;                         /* MAC entries really put into the list (-1 = nsta) */
    int list_mac_len;                         /* length of every list entry */
    unsigned long long tx_bytes, tx_pkts, failed;  /* TX_BYTES64, TX_PACKETS64, TX_FAILED_RETRIES of every station */
    unsigned std; unsigned bw;                /* OPER_STANDARD (u32) and OPER_CHANNEL_BW (u8) values */
    int mld, mld_mac_len;                     /* MLD_ENAB value (-1 = attribute absent), MLD_MAC attribute length (0 = absent) */
    int mac_len;                              /* length of the RDK_VENDOR_ATTR_MAC attribute of a stats reply */
    int omit;                                 /* 0 none, 1 reply without RDK_VENDOR_ATTR_MAC, 2 without RDK_VENDOR_ATTR_STA_INFO, 3 without vendor data */
    int calloc_calls, cmd_calls, send_calls, live;
} bga_world_t;
extern bga_world_t hwr_bga_world;

#ifdef __cplusplus
extern "C" {
#endif
INT hwr_bcm_wifi_getApAssociatedDeviceDiagnosticResult3(INT apIndex, wifi_associated_dev3_t **associated_dev_array, UINT *output_array_size);
#ifdef __cplusplus
}
#endif

/* name, ap_index, has_iface, args (1 array ptr NULL, 2 size ptr NULL, 3 both), nsta, tx_bytes, tx_pkts, failed, std, bw, mld, mld_mac_len, mac_len,
 * sta_num, list_entries, list_mac_len, omit, list_cmd_fail, stats_cmd_fail, dump_rc, stats_fail_idx, fail_calloc, calloc_limit, calls,
 * expected_ret, exp_size (-1 = nsta), exp_untouched, exp_null_out, last */
typedef struct {
    const char *test_name;
    int ap_index, has_iface, args, nsta;
    unsigned long long tx_bytes, tx_pkts, failed;
    unsigned std, bw; int mld, mld_mac_len, mac_len;
    long long sta_num; int list_entries, list_mac_len, omit;
    int list_cmd_fail, stats_cmd_fail, dump_rc, stats_fail_idx, fail_calloc; unsigned long calloc_limit;
    int calls, expected_ret, exp_size, exp_untouched, exp_null_out, last;
} bga_case_t;
extern bga_case_t bcm_wifi_getApAssociatedDeviceDiagnosticResult3_suite[];
#ifdef __cplusplus
extern "C" void run_all_tests_bcm_wifi_getApAssociatedDeviceDiagnosticResult3(void);
#endif
#endif
