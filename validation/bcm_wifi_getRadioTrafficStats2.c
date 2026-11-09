/*
 * HANDLER: wifi_getRadioTrafficStats2 (platform/broadcom)
 *
 * Functions copied VERBATIM from rdk-wifi-hal (~/Desktop/G/rdk-wifi-hal): platform/broadcom/platform.c:4177-4372 - get_radio_diag_handler,
 * get_radio_diagnostics and wifi_getRadioTrafficStats2.  This file holds the ORIGINAL code with fixes 1-2 applied (start fix n / end fix n markers; the unfixed copy is the reproducer).  The netlink handler is the REAL one,
 * running on real libnl messages.  Compiled as C.
 *
 * Scaffolding only (the Broadcom vendor header rdk_nl80211_hal.h is not in the source tree, so the RDK_VENDOR_* numbers below are the harness's own):
 *  - nl80211_drv_vendor_cmd_msg / nl80211_drv_cmd_msg: the real bodies (wifi_hal_nl80211.c:4083 / 4061); the runner can make the command message NULL.
 *  - nl80211_send_and_recv: the "kernel": calls the handler once with a vendor-data nest holding RDK_VENDOR_ATTR_RADIO_INFO with the 21 statistics
 *    (one of them optionally left out).  The reply is an exact-size heap block (nlmsg_convert); the request is freed like the real one.
 *  - get_radio_by_rdk_index / get_primary_interface: runner-controlled lookups.  The print macros map to the log sink hwr_print (runner-poisoned slot).
 */
#include "hwr_bgt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define wifi_hal_stats_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define wifi_hal_stats_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_radio_info_t bgt_radio_t
#define wifi_interface_info_t bgt_iface_t
#define wifi_getRadioTrafficStats2 hwr_bcm_wifi_getRadioTrafficStats2
#define OUI_COMCAST 0x001018

enum { RDK_VENDOR_ATTR_INVALID, RDK_VENDOR_ATTR_RADIO_INFO, RDK_VENDOR_ATTR_MAX = RDK_VENDOR_ATTR_RADIO_INFO };
enum { RDK_VENDOR_ATTR_RADIO_INFO_INVALID,
       RDK_VENDOR_ATTR_RADIO_INFO_BYTES_SENT, RDK_VENDOR_ATTR_RADIO_INFO_BYTES_RECEIVED, RDK_VENDOR_ATTR_RADIO_INFO_PACKETS_SENT,
       RDK_VENDOR_ATTR_RADIO_INFO_PACKETS_RECEIVED, RDK_VENDOR_ATTR_RADIO_INFO_ERRORS_SENT, RDK_VENDOR_ATTR_RADIO_INFO_ERRORS_RECEIVED,
       RDK_VENDOR_ATTR_RADIO_INFO_DISCARD_PACKETS_SENT, RDK_VENDOR_ATTR_RADIO_INFO_DISCARD_PACKETS_RECEIVED, RDK_VENDOR_ATTR_RADIO_INFO_PLCP_ERRORS_COUNT,
       RDK_VENDOR_ATTR_RADIO_INFO_FCS_ERRORS_COUNT, RDK_VENDOR_ATTR_RADIO_INFO_INVALID_MAC_COUNT, RDK_VENDOR_ATTR_RADIO_INFO_PACKETS_OTHER_RECEIVED,
       RDK_VENDOR_ATTR_RADIO_INFO_NOISE_FLOOR, RDK_VENDOR_ATTR_RADIO_INFO_CHANNEL_UTILIZATION, RDK_VENDOR_ATTR_RADIO_INFO_ACTIVITY_FACTOR,
       RDK_VENDOR_ATTR_RADIO_INFO_CARRIERSENSE_THRESHOLD, RDK_VENDOR_ATTR_RADIO_INFO_RETRANSMISSION, RDK_VENDOR_ATTR_RADIO_INFO_MAX_NOISE_FLOOR,
       RDK_VENDOR_ATTR_RADIO_INFO_MIN_NOISE_FLOOR, RDK_VENDOR_ATTR_RADIO_INFO_MEDIAN_NOISE_FLOOR, RDK_VENDOR_ATTR_RADIO_INFO_STATS_START_TIME,
       RDK_VENDOR_ATTR_RADIO_INFO_MAX = RDK_VENDOR_ATTR_RADIO_INFO_STATS_START_TIME };
enum { RDK_VENDOR_NL80211_SUBCMD_GET_RADIO_INFO = 4 };

bgt_world_t hwr_bgt_world;
static struct { int nl80211_id; } g_wifi_hal = { 28 };

static bgt_radio_t *get_radio_by_rdk_index(int index)
{
    return (hwr_bgt_world.radio && hwr_bgt_world.radio->rdk_index == index) ? hwr_bgt_world.radio : NULL;
}
static bgt_iface_t *get_primary_interface(bgt_radio_t *radio) { return radio->primary; }

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

    hwr_bgt_world.cmd_calls++;
    if (hwr_bgt_world.cmd_fail) return NULL;
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

/* ---- the kernel side: statistic i (1..21) has the value base + i, the signed ones -(50 + i + (base & 7)) ---- */
static struct nl_msg *build_reply(bgt_world_t *w)
{
    struct nl_msg *m = nlmsg_alloc_size(65536), *ex;

    genlmsg_put(m, 0, 0, 0, 0, 0, NL80211_CMD_VENDOR, 0);
    if (w->omit_reply != 1) {
        struct nlattr *v = nla_nest_start(m, NL80211_ATTR_VENDOR_DATA);
        if (w->omit_reply != 2) {
            struct nlattr *ri = nla_nest_start(m, RDK_VENDOR_ATTR_RADIO_INFO);
            for (int i = 1; i <= RDK_VENDOR_ATTR_RADIO_INFO_MAX; i++) {
                if (i == w->omit_attr) continue;
                if (i >= RDK_VENDOR_ATTR_RADIO_INFO_NOISE_FLOOR && i != RDK_VENDOR_ATTR_RADIO_INFO_CHANNEL_UTILIZATION &&
                    i != RDK_VENDOR_ATTR_RADIO_INFO_STATS_START_TIME)
                    nla_put_s32(m, i, -(50 + i + (int)(w->base & 7)));
                else
                    nla_put_u64(m, i, w->base + (unsigned long long)i);
            }
            nla_nest_end(m, ri);
        }
        nla_nest_end(m, v);
    }
    ex = nlmsg_convert(nlmsg_hdr(m));
    nlmsg_free(m);
    return ex;
}

static int nl80211_send_and_recv(struct nl_msg *msg, int (*valid_handler)(struct nl_msg *, void *), void *valid_data,
    int (*valid_finish_handler)(struct nl_msg *, void *), void *valid_finish_data)
{
    struct nl_msg *r;

    (void)valid_finish_handler; (void)valid_finish_data;
    hwr_bgt_world.send_calls++;
    r = build_reply(&hwr_bgt_world);
    valid_handler(r, valid_data);
    nlmsg_free(r);
    nlmsg_free(msg);
    return hwr_bgt_world.dump_rc;
}

/* --- platform.c:4177-4372 --- */
/* start fix 2 */
typedef struct {
    wifi_radioTrafficStats2_t *stats;
    int received;
} radio_diag_ctx_t;
/* end fix 2 */

static int get_radio_diag_handler(struct nl_msg *msg, void *arg)
{
    int i;
    struct nlattr *nlattr;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *tb_vendor[RDK_VENDOR_ATTR_MAX + 1];
    struct nlattr *tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    static struct nla_policy vendor_policy[RDK_VENDOR_ATTR_MAX + 1] = {
        [RDK_VENDOR_ATTR_RADIO_INFO] = { .type = NLA_NESTED },
    };
    static struct nla_policy radio_diag_policy[RDK_VENDOR_ATTR_RADIO_INFO_MAX + 1] = {
        [RDK_VENDOR_ATTR_RADIO_INFO_BYTES_SENT] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_BYTES_RECEIVED] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_PACKETS_SENT] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_PACKETS_RECEIVED] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_ERRORS_SENT] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_ERRORS_RECEIVED] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_DISCARD_PACKETS_SENT] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_DISCARD_PACKETS_RECEIVED] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_PLCP_ERRORS_COUNT] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_FCS_ERRORS_COUNT] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_INVALID_MAC_COUNT] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_PACKETS_OTHER_RECEIVED] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_NOISE_FLOOR] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_RADIO_INFO_CHANNEL_UTILIZATION] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_ACTIVITY_FACTOR] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_RADIO_INFO_CARRIERSENSE_THRESHOLD] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_RADIO_INFO_RETRANSMISSION] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_RADIO_INFO_MAX_NOISE_FLOOR] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_RADIO_INFO_MIN_NOISE_FLOOR] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_RADIO_INFO_MEDIAN_NOISE_FLOOR] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_RADIO_INFO_STATS_START_TIME] = { .type = NLA_U64 },
    };
    /* start fix 2 */
    wifi_radioTrafficStats2_t *radioTrafficStats = ((radio_diag_ctx_t *)arg)->stats;
    /* end fix 2 */

    if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL) <
        0) {
        wifi_hal_stats_error_print("%s:%d Failed to parse vendor data\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (tb[NL80211_ATTR_VENDOR_DATA] == NULL) {
        wifi_hal_stats_error_print("%s:%d Vendor data is missing\n", __func__, __LINE__);
        return NL_SKIP;
    }

    nlattr = tb[NL80211_ATTR_VENDOR_DATA];
    if (nla_parse(tb_vendor, RDK_VENDOR_ATTR_MAX, nla_data(nlattr), nla_len(nlattr),
            vendor_policy) < 0) {
        wifi_hal_stats_error_print("%s:%d Failed to parse vendor attribute\n", __func__, __LINE__);
        return NL_SKIP;
    }

    for (i = 0; i <= RDK_VENDOR_ATTR_MAX; i++) {
        if (vendor_policy[i].type != 0 && tb_vendor[i] == NULL) {
            wifi_hal_stats_error_print("%s:%d Vendor attribute %d is missing\n", __func__, __LINE__, i);
            return NL_SKIP;
        }
    }

    if (nla_parse_nested(tb_radio_info, RDK_VENDOR_ATTR_RADIO_INFO_MAX,
            tb_vendor[RDK_VENDOR_ATTR_RADIO_INFO], radio_diag_policy)) {
        wifi_hal_stats_error_print("%s:%d Failed to parse radio info attribute\n", __func__, __LINE__);
        return NL_SKIP;
    }

    for (i = 0; i <= RDK_VENDOR_ATTR_RADIO_INFO_MAX; i++) {
        if (radio_diag_policy[i].type != 0 && tb_radio_info[i] == NULL) {
            wifi_hal_stats_error_print("%s:%d radio info attribute %d is missing\n", __func__, __LINE__,
                i);
            return NL_SKIP;
        }
    }

    radioTrafficStats->radio_BytesSent = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_BYTES_SENT]);
    radioTrafficStats->radio_BytesReceived = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_BYTES_RECEIVED]);
    radioTrafficStats->radio_PacketsSent = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_PACKETS_SENT]);
    radioTrafficStats->radio_PacketsReceived = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_PACKETS_RECEIVED]);
    radioTrafficStats->radio_ErrorsSent = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_ERRORS_SENT]);
    radioTrafficStats->radio_ErrorsReceived = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_ERRORS_RECEIVED]);
    radioTrafficStats->radio_DiscardPacketsSent = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_DISCARD_PACKETS_SENT]);
    radioTrafficStats->radio_DiscardPacketsReceived = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_DISCARD_PACKETS_RECEIVED]);
    radioTrafficStats->radio_PLCPErrorCount = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_PLCP_ERRORS_COUNT]);
    radioTrafficStats->radio_FCSErrorCount = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_FCS_ERRORS_COUNT]);
    radioTrafficStats->radio_InvalidMACCount = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_INVALID_MAC_COUNT]);
    radioTrafficStats->radio_PacketsOtherReceived = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_PACKETS_OTHER_RECEIVED]);
    radioTrafficStats->radio_NoiseFloor = nla_get_s32(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_NOISE_FLOOR]);
    radioTrafficStats->radio_ChannelUtilization = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_CHANNEL_UTILIZATION]);
    radioTrafficStats->radio_ActivityFactor = nla_get_s32(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_ACTIVITY_FACTOR]);
    radioTrafficStats->radio_CarrierSenseThreshold_Exceeded = nla_get_s32(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_CARRIERSENSE_THRESHOLD]);
    radioTrafficStats->radio_RetransmissionMetirc = nla_get_s32(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_RETRANSMISSION]);
    radioTrafficStats->radio_MaximumNoiseFloorOnChannel = nla_get_s32(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_MAX_NOISE_FLOOR]);
    radioTrafficStats->radio_MinimumNoiseFloorOnChannel = nla_get_s32(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_MIN_NOISE_FLOOR]);
    radioTrafficStats->radio_MedianNoiseFloorOnChannel = nla_get_s32(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_MEDIAN_NOISE_FLOOR]);
    radioTrafficStats->radio_StatisticsStartTime = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_STATS_START_TIME]);

    wifi_hal_stats_dbg_print(
        "%s:%d radio_BytesSent %lu radio_BytesReceived %lu radio_PacketsSent %lu "
        "radio_PacketsReceived %lu radio_ErrorsSent %lu radio_ErrorsReceived %lu "
        "radio_DiscardPacketsSent %lu radio_DiscardPacketsReceived %lu radio_PLCPErrorCount %lu "
        "radio_FCSErrorCount %lu radio_InvalidMACCount %lu radio_PacketsOtherReceived %lu "
        "radio_NoiseFloor %d radio_ChannelUtilization %lu radio_ActivityFactor %d "
        "radio_CarrierSenseThreshold_Exceeded %d radio_RetransmissionMetirc %d, "
        "radio_MaximumNoiseFloorOnChannel %d radio_MinimumNoiseFloorOnChannel %d "
        "radio_MedianNoiseFloorOnChannel %d radio_StatisticsStartTime %lu",
        __func__, __LINE__, radioTrafficStats->radio_BytesSent,
        radioTrafficStats->radio_BytesReceived, radioTrafficStats->radio_PacketsSent,
        radioTrafficStats->radio_PacketsReceived, radioTrafficStats->radio_ErrorsSent,
        radioTrafficStats->radio_ErrorsReceived, radioTrafficStats->radio_DiscardPacketsSent,
        radioTrafficStats->radio_DiscardPacketsReceived, radioTrafficStats->radio_PLCPErrorCount,
        radioTrafficStats->radio_FCSErrorCount, radioTrafficStats->radio_InvalidMACCount,
        radioTrafficStats->radio_PacketsOtherReceived, radioTrafficStats->radio_NoiseFloor,
        radioTrafficStats->radio_ChannelUtilization, radioTrafficStats->radio_ActivityFactor,
        radioTrafficStats->radio_CarrierSenseThreshold_Exceeded,
        radioTrafficStats->radio_RetransmissionMetirc,
        radioTrafficStats->radio_MaximumNoiseFloorOnChannel,
        radioTrafficStats->radio_MinimumNoiseFloorOnChannel,
        radioTrafficStats->radio_MedianNoiseFloorOnChannel,
        radioTrafficStats->radio_StatisticsStartTime);
    /* start fix 2 */
    ((radio_diag_ctx_t *)arg)->received = 1;
    /* end fix 2 */
    return NL_SKIP;
}

static int get_radio_diagnostics(wifi_interface_info_t *interface,
    wifi_radioTrafficStats2_t *radioTrafficStats)
{
    struct nl_msg *msg;
    int ret = RETURN_ERR;
    /* start fix 2 */
    radio_diag_ctx_t ctx = { .stats = radioTrafficStats, .received = 0 };
    /* end fix 2 */

    wifi_hal_stats_dbg_print("%s:%d Entering\n", __func__, __LINE__);
    msg = nl80211_drv_vendor_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, OUI_COMCAST,
        RDK_VENDOR_NL80211_SUBCMD_GET_RADIO_INFO);
    if (msg == NULL) {
        wifi_hal_stats_error_print("%s:%d Failed to create NL command\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    /* start fix 2 */
    ret = nl80211_send_and_recv(msg, get_radio_diag_handler, &ctx, NULL, NULL);
    /* end fix 2 */
    if (ret) {
        wifi_hal_stats_error_print("%s:%d Failed to send NL message\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    /* start fix 2 */
    if (!ctx.received) {
        wifi_hal_stats_error_print("%s:%d No valid radio info in the reply\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    /* end fix 2 */

    return RETURN_OK;
}

INT wifi_getRadioTrafficStats2(INT radioIndex, wifi_radioTrafficStats2_t *radioTrafficStats)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;

    wifi_hal_stats_dbg_print("%s:%d: Get radio traffic stats for index: %d\n", __func__, __LINE__,
        radioIndex);

    /* start fix 1 */
    if (radioTrafficStats == NULL) {
        wifi_hal_stats_error_print("%s:%d: NULL radioTrafficStats\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    /* end fix 1 */

    radio = get_radio_by_rdk_index(radioIndex);
    if (radio == NULL) {
        wifi_hal_stats_error_print("%s:%d: Failed to get radio for index: %d\n", __func__, __LINE__,
            radioIndex);
        return RETURN_ERR;
    }

    interface = get_primary_interface(radio);
    if (interface == NULL) {
        wifi_hal_stats_error_print("%s:%d: Failed to get interface for radio index: %d\n", __func__,
            __LINE__, radioIndex);
        return RETURN_ERR;
    }
    if (get_radio_diagnostics(interface, radioTrafficStats)) {
        wifi_hal_stats_error_print("%s:%d: Failed to get radio diagnostics stats for radio index: %d\n",
            __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }

    return RETURN_OK;
}
