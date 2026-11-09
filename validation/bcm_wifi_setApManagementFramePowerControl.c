/*
 * HANDLER: wifi_setApManagementFramePowerControl (platform/broadcom)
 *
 * Functions copied VERBATIM from rdk-wifi-hal (~/Desktop/G/rdk-wifi-hal): platform/broadcom/platform.c:4373-4427 - set_ap_pwr and
 * wifi_setApManagementFramePowerControl.  This file holds the ORIGINAL code: no fix is applied.  Compiled as C.
 *
 * Scaffolding only (the Broadcom vendor header rdk_nl80211_hal.h is not in the source tree, so the RDK_VENDOR_* numbers below are the harness's own):
 *  - nl80211_drv_vendor_cmd_msg / nl80211_drv_cmd_msg: the real bodies (wifi_hal_nl80211.c:4083 / 4061); the runner can make the command message NULL or
 *    shrink libnl's default message size (nlmsg_set_default_size), so that the nest / the power attribute no longer fit.
 *  - nl80211_send_and_recv: the "driver": parses the request (interface index, wiphy, vendor id, sub-command, the power attribute inside the vendor-data
 *    nest) into the world for the runner to check, returns the runner's result and frees the request like the real one.
 *  - get_interface_by_vap_index: runner-controlled lookup.  The print macros map to the log sink hwr_print (runner-poisoned slot).
 */
#include "hwr_bsp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_interface_info_t bsp_iface_t
#define wifi_setApManagementFramePowerControl hwr_bcm_wifi_setApManagementFramePowerControl
#define OUI_COMCAST 0x001018

enum { RDK_VENDOR_ATTR_MGT_FRAME_PWR_INVALID, RDK_VENDOR_ATTR_MGT_FRAME_PWR_LEVEL, RDK_VENDOR_ATTR_MGT_FRAME_PWR_MAX = RDK_VENDOR_ATTR_MGT_FRAME_PWR_LEVEL };
enum { RDK_VENDOR_NL80211_SUBCMD_SET_MGT_FRAME_PWR = 7 };

bsp_world_t hwr_bsp_world;
static struct { int nl80211_id; } g_wifi_hal = { 28 };

static bsp_iface_t *get_interface_by_vap_index(unsigned int vap_index)
{
    return (hwr_bsp_world.iface && hwr_bsp_world.iface->vap_index == vap_index) ? hwr_bsp_world.iface : NULL;
}

/* --- wifi_hal_nl80211.c:4061 --- */
static struct nl_msg *nl80211_drv_cmd_msg(int nl80211_id, wifi_interface_info_t *intf, int flags, uint8_t cmd)
{
    struct nl_msg *msg;

    msg = nlmsg_alloc();
    if (msg == NULL) {
        return NULL;
    }

    if (genlmsg_put(msg, 0, 0, nl80211_id, 0, flags, cmd, 0) == NULL) {
        nlmsg_free(msg);
        return NULL;
    }

    if (intf != NULL) {
        nla_put_u32(msg, NL80211_ATTR_IFINDEX, intf->index);
        nla_put_u32(msg, NL80211_ATTR_WIPHY, intf->phy_index);
    }

    return msg;
}

/* --- wifi_hal_nl80211.c:4083 --- */
static struct nl_msg *nl80211_drv_vendor_cmd_msg(int nl80211_id, wifi_interface_info_t *intf, int flags,
    uint32_t vendor_id, uint32_t subcmd)
{
    struct nl_msg *msg;

    hwr_bsp_world.cmd_calls++;
    if (hwr_bsp_world.cmd_fail) return NULL;
    if (hwr_bsp_world.room) nlmsg_set_default_size(hwr_bsp_world.room);
    msg = nl80211_drv_cmd_msg(nl80211_id, intf, flags, NL80211_CMD_VENDOR);
    if (msg == NULL) {
        return NULL;
    }

    if (nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, vendor_id) < 0) {
        goto error;
    }

    if (nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD, subcmd) < 0) {
        goto error;
    }

    return msg;

error:
    nlmsg_free(msg);
    return NULL;
}

/* the "driver" */
static int nl80211_send_and_recv(struct nl_msg *msg, int (*valid_handler)(struct nl_msg *, void *), void *valid_data,
    int (*valid_finish_handler)(struct nl_msg *, void *), void *valid_finish_data)
{
    bsp_world_t *w = &hwr_bsp_world;
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct genlmsghdr *g = (struct genlmsghdr *)nlmsg_data(nlh);
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *tp[RDK_VENDOR_ATTR_MGT_FRAME_PWR_MAX + 1];

    (void)valid_handler; (void)valid_data; (void)valid_finish_handler; (void)valid_finish_data;
    w->send_calls++;
    w->req_ok = nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(g, 0), genlmsg_attrlen(g, 0), NULL) >= 0;
    if (w->req_ok) {
        if (tb[NL80211_ATTR_IFINDEX]) w->got_ifindex = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);
        if (tb[NL80211_ATTR_WIPHY]) w->got_phy = nla_get_u32(tb[NL80211_ATTR_WIPHY]);
        if (tb[NL80211_ATTR_VENDOR_ID]) w->got_vendor = nla_get_u32(tb[NL80211_ATTR_VENDOR_ID]);
        if (tb[NL80211_ATTR_VENDOR_SUBCMD]) w->got_subcmd = nla_get_u32(tb[NL80211_ATTR_VENDOR_SUBCMD]);
        if (tb[NL80211_ATTR_VENDOR_DATA]) {
            w->got_have_nest = 1;
            if (nla_parse(tp, RDK_VENDOR_ATTR_MGT_FRAME_PWR_MAX, nla_data(tb[NL80211_ATTR_VENDOR_DATA]), nla_len(tb[NL80211_ATTR_VENDOR_DATA]), NULL) >= 0 &&
                tp[RDK_VENDOR_ATTR_MGT_FRAME_PWR_LEVEL]) {
                w->got_len = nla_len(tp[RDK_VENDOR_ATTR_MGT_FRAME_PWR_LEVEL]);
                if (w->got_len == 4) w->got_pwr = *(int *)nla_data(tp[RDK_VENDOR_ATTR_MGT_FRAME_PWR_LEVEL]);
            }
        }
    }
    nlmsg_free(msg);
    return w->send_rc;
}

/* --- platform.c:4373-4427 --- */
static int set_ap_pwr(wifi_interface_info_t *interface, INT *power)
{
    struct nlattr *nlattr;
    struct nl_msg *msg;
    int ret = RETURN_ERR;

    msg = nl80211_drv_vendor_cmd_msg(g_wifi_hal.nl80211_id, interface, 0,
                                     OUI_COMCAST,
                                     RDK_VENDOR_NL80211_SUBCMD_SET_MGT_FRAME_PWR);

    if (msg == NULL) {
        wifi_hal_error_print("%s:%d Failed to create NL command\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    nlattr = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);

    if (nla_put(msg, RDK_VENDOR_ATTR_MGT_FRAME_PWR_LEVEL, sizeof(*power), power) < 0) {
        wifi_hal_error_print("%s:%d Failed to put AP power\n", __func__, __LINE__);
        nlmsg_free(msg);
        return RETURN_ERR;
    }
    nla_nest_end(msg, nlattr);

    ret = nl80211_send_and_recv(msg, NULL, power, NULL, NULL);

    if (ret) {
        wifi_hal_error_print("%s:%d Failed to send NL message: %d (%s)\n", __func__, __LINE__, ret, strerror(-ret));
        return RETURN_ERR;
    }

    return RETURN_OK;
}

INT wifi_setApManagementFramePowerControl(INT apIndex, INT dBm)
{
    wifi_interface_info_t *interface;

    wifi_hal_dbg_print("%s:%d: Set AP management frame for index: %d\n", __func__, __LINE__,
        apIndex);

    interface = get_interface_by_vap_index(apIndex);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: Failed to get interface for ap index: %d\n", __func__,
            __LINE__, apIndex);
        return RETURN_ERR;
    }
    if (set_ap_pwr(interface, &dBm)) {
        wifi_hal_error_print("%s:%d: Failed to set ap power for ap index: %d\n", __func__,
            __LINE__, apIndex);
        return RETURN_ERR;
    }

    return RETURN_OK;
}
