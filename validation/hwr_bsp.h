/* hwr_bsp.h - plumbing for the broadcom wifi_setApManagementFramePowerControl harness (platform/broadcom) */
#ifndef HWR_BSP_H
#define HWR_BSP_H
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

typedef struct { unsigned int vap_index; unsigned int index; unsigned int phy_index; } bsp_iface_t;

typedef struct {
    bsp_iface_t *iface;
    int cmd_fail, send_rc, room;      /* command message NULL; result of nl80211_send_and_recv; libnl default message size (0 = default) */
    /* what the "driver" received */
    int send_calls, cmd_calls, req_ok;
    unsigned got_vendor, got_subcmd, got_ifindex, got_phy; int got_pwr, got_len, got_have_nest, got_nlen;
    int msgs_freed;
} bsp_world_t;
extern bsp_world_t hwr_bsp_world;

#ifdef __cplusplus
extern "C" {
#endif
INT hwr_bcm_wifi_setApManagementFramePowerControl(INT apIndex, INT dBm);
#ifdef __cplusplus
}
#endif

typedef struct {
    const char *test_name;
    int ap_index, has_iface, dbm;
    int cmd_fail, send_rc, room;
    int calls, expected_ret, expect_sent;      /* expect_sent: the vendor command reaches the "driver" */
} bsp_case_t;
extern bsp_case_t bcm_wifi_setApManagementFramePowerControl_suite[];
#ifdef __cplusplus
extern "C" void run_all_tests_bcm_wifi_setApManagementFramePowerControl(void);
#endif
#endif
