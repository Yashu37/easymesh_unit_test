/*
 * HANDLER: wifi_getApAssociatedDeviceDiagnosticResult3 (platform/broadcom)
 *
 * Functions copied VERBATIM from rdk-wifi-hal (~/Desktop/G/rdk-wifi-hal): platform/broadcom/platform.c:3502-4013 - the sta_list_t type, get_sta_list_handler,
 * get_sta_list, standard_to_str, bw_to_str, get_sta_stats_handler, get_sta_stats and wifi_getApAssociatedDeviceDiagnosticResult3.  This file holds the
 * ORIGINAL code with fixes 1-4 applied (start fix n / end fix n markers; the unfixed copy is the reproducer).  The netlink handlers are the REAL ones, running on real libnl messages.  Compiled as C (the verbatim code uses
 * out-of-order designated initializers).
 *
 * Scaffolding only (the Broadcom vendor header rdk_nl80211_hal.h is not part of the source tree, so the RDK_VENDOR_* attribute numbers below are the
 * harness's own - the code only uses the symbolic names; the real wifi_associated_dev3_t is used):
 *  - nl80211_drv_vendor_cmd_msg (wifi_hal_nl80211.c:4083) and nl80211_drv_cmd_msg (4061): the real bodies over a plain interface; the runner can make
 *    them fail.
 *  - nl80211_send_and_recv: the "kernel".  For GET_STATION_LIST it calls the handler once with a vendor-data nest holding RDK_VENDOR_ATTR_STA_NUM and
 *    RDK_VENDOR_ATTR_STA_LIST (one MAC entry per station); for GET_STATION it reads the MAC attribute of the request, finds the station and calls the
 *    handler with RDK_VENDOR_ATTR_MAC and an RDK_VENDOR_ATTR_STA_INFO nest of attributes built from the world.  Every reply is copied into an exact-size
 *    heap block (nlmsg_convert), so a read behind the message is an ASan overflow.  The request is freed like the real one.
 *  - get_interface_by_vap_index: runner-controlled lookup.  calloc / free over counting wrappers (live blocks; the runner can make calloc fail or fail
 *    above a size limit).  The print macros are mapped to the log sink hwr_print (runner-poisoned slot).
 */
#include "hwr_bga.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define CONFIG_IEEE80211BE 1
#define wifi_hal_stats_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define wifi_hal_stats_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_interface_info_t bga_interface_t
#define wifi_getApAssociatedDeviceDiagnosticResult3 hwr_bcm_wifi_getApAssociatedDeviceDiagnosticResult3
#define WIFI_BLASTER_DEFAULT_PKTSIZE 1470
#define ETHER_ADDR_LEN 6
#define OUI_COMCAST 0x001018

enum { RDK_VENDOR_ATTR_INVALID, RDK_VENDOR_ATTR_MAC, RDK_VENDOR_ATTR_STA_NUM, RDK_VENDOR_ATTR_STA_LIST, RDK_VENDOR_ATTR_STA_INFO,
       RDK_VENDOR_ATTR_MAX = RDK_VENDOR_ATTR_STA_INFO };
enum { RDK_VENDOR_ATTR_STA_INFO_INVALID,
       RDK_VENDOR_ATTR_STA_INFO_STA_FLAGS, RDK_VENDOR_ATTR_STA_INFO_RX_BITRATE_LAST, RDK_VENDOR_ATTR_STA_INFO_TX_BITRATE_LAST,
       RDK_VENDOR_ATTR_STA_INFO_SIGNAL_AVG, RDK_VENDOR_ATTR_STA_INFO_SIGNAL_MIN, RDK_VENDOR_ATTR_STA_INFO_SIGNAL_MAX,
       RDK_VENDOR_ATTR_STA_INFO_TX_RETRIES_PERCENT, RDK_VENDOR_ATTR_STA_INFO_ACTIVE, RDK_VENDOR_ATTR_STA_INFO_OPER_STANDARD,
       RDK_VENDOR_ATTR_STA_INFO_OPER_CHANNEL_BW, RDK_VENDOR_ATTR_STA_INFO_SNR, RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS_ACK,
       RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS_NO_ACK, RDK_VENDOR_ATTR_STA_INFO_TX_BYTES64, RDK_VENDOR_ATTR_STA_INFO_RX_BYTES64,
       RDK_VENDOR_ATTR_STA_INFO_AUTH_FAILS, RDK_VENDOR_ATTR_STA_INFO_ASSOC_NUM, RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS64,
       RDK_VENDOR_ATTR_STA_INFO_RX_PACKETS64, RDK_VENDOR_ATTR_STA_INFO_TX_ERRORS, RDK_VENDOR_ATTR_STA_INFO_TX_RETRANSMIT,
       RDK_VENDOR_ATTR_STA_INFO_TX_FAILED_RETRIES, RDK_VENDOR_ATTR_STA_INFO_TX_RETRIES, RDK_VENDOR_ATTR_STA_INFO_TX_MULT_RETRIES,
       RDK_VENDOR_ATTR_STA_INFO_TX_RATE_MAX, RDK_VENDOR_ATTR_STA_INFO_RX_RATE_MAX, RDK_VENDOR_ATTR_STA_INFO_SPATIAL_STREAM_NUM,
       RDK_VENDOR_ATTR_STA_INFO_ACTIVE_SPATIAL_STREAM_NUM, RDK_VENDOR_ATTR_STA_INFO_TX_FRAMES, RDK_VENDOR_ATTR_STA_INFO_RX_RETRIES,
       RDK_VENDOR_ATTR_STA_INFO_RX_ERRORS, RDK_VENDOR_ATTR_STA_INFO_MLD_MAC, RDK_VENDOR_ATTR_STA_INFO_MLD_ENAB,
       RDK_VENDOR_ATTR_STA_INFO_POWER_SAVE, RDK_VENDOR_ATTR_STA_INFO_PS_SLEEP_TIME_MS,
       RDK_VENDOR_ATTR_STA_INFO_MAX = RDK_VENDOR_ATTR_STA_INFO_PS_SLEEP_TIME_MS };
enum { RDK_VENDOR_NL80211_STANDARD_INVALID, RDK_VENDOR_NL80211_STANDARD_A, RDK_VENDOR_NL80211_STANDARD_B, RDK_VENDOR_NL80211_STANDARD_G,
       RDK_VENDOR_NL80211_STANDARD_N, RDK_VENDOR_NL80211_STANDARD_AC, RDK_VENDOR_NL80211_STANDARD_AD, RDK_VENDOR_NL80211_STANDARD_AX,
       RDK_VENDOR_NL80211_STANDARD_BE };
enum { RDK_VENDOR_NL80211_CHAN_WIDTH_INVALID, RDK_VENDOR_NL80211_CHAN_WIDTH_20, RDK_VENDOR_NL80211_CHAN_WIDTH_40, RDK_VENDOR_NL80211_CHAN_WIDTH_80,
       RDK_VENDOR_NL80211_CHAN_WIDTH_160, RDK_VENDOR_NL80211_CHAN_WIDTH_320 };
enum { RDK_VENDOR_NL80211_SUBCMD_GET_STATION = 1, RDK_VENDOR_NL80211_SUBCMD_GET_STATION_LIST = 2 };

bga_world_t hwr_bga_world;
static struct { int nl80211_id; } g_wifi_hal = { 28 };

static bga_interface_t *get_interface_by_vap_index(unsigned int vap_index)
{
    return (hwr_bga_world.iface && hwr_bga_world.iface->vap_index == vap_index) ? hwr_bga_world.iface : NULL;
}

/* allocation the runner can make fail, and count of live blocks */
static void *bga_calloc(size_t n, size_t s)
{
    hwr_bga_world.calloc_calls++;
    if (hwr_bga_world.fail_calloc && hwr_bga_world.calloc_calls >= 2) return NULL;   /* the 2nd calloc = the entry array (the 1st is the MAC list) */
    if (hwr_bga_world.calloc_limit && (unsigned long long)n * s > hwr_bga_world.calloc_limit) return NULL;
    void *p = calloc(n, s); if (p) hwr_bga_world.live++; return p;
}
static void bga_free(void *p) { if (p) hwr_bga_world.live--; free(p); }
#define calloc bga_calloc
#define free   bga_free

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

    hwr_bga_world.cmd_calls++;
    if (subcmd == RDK_VENDOR_NL80211_SUBCMD_GET_STATION_LIST ? hwr_bga_world.list_cmd_fail : hwr_bga_world.stats_cmd_fail) return NULL;
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

/* ---- the kernel side ---- */
static void put_info(struct nl_msg *m, bga_world_t *w, int idx)
{
    struct nlattr *nest = nla_nest_start(m, RDK_VENDOR_ATTR_STA_INFO);
    struct nl80211_sta_flag_update fl;

    memset(&fl, 0, sizeof(fl));
    fl.mask = (1 << NL80211_STA_FLAG_AUTHORIZED) | (1 << NL80211_STA_FLAG_WME);
    fl.set = ((idx & 1) == 0 ? (1 << NL80211_STA_FLAG_AUTHORIZED) : 0) | (1 << NL80211_STA_FLAG_WME);
    nla_put(m, RDK_VENDOR_ATTR_STA_INFO_STA_FLAGS, sizeof(fl), &fl);
    nla_put_u32(m, RDK_VENDOR_ATTR_STA_INFO_RX_BITRATE_LAST, 1000 + idx);
    nla_put_u32(m, RDK_VENDOR_ATTR_STA_INFO_TX_BITRATE_LAST, 2000 + idx);
    nla_put_s32(m, RDK_VENDOR_ATTR_STA_INFO_SIGNAL_AVG, -50 - idx);
    nla_put_s32(m, RDK_VENDOR_ATTR_STA_INFO_SIGNAL_MIN, -90);
    nla_put_s32(m, RDK_VENDOR_ATTR_STA_INFO_SIGNAL_MAX, -30);
    nla_put_u32(m, RDK_VENDOR_ATTR_STA_INFO_TX_RETRIES_PERCENT, 5 + idx);
    nla_put_u8(m, RDK_VENDOR_ATTR_STA_INFO_ACTIVE, 1);
    nla_put_u32(m, RDK_VENDOR_ATTR_STA_INFO_OPER_STANDARD, w->std);
    nla_put_u8(m, RDK_VENDOR_ATTR_STA_INFO_OPER_CHANNEL_BW, (uint8_t)w->bw);
    nla_put_s32(m, RDK_VENDOR_ATTR_STA_INFO_SNR, 30 + idx);
    nla_put_u64(m, RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS_ACK, 7);
    nla_put_u64(m, RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS_NO_ACK, 3);
    nla_put_u64(m, RDK_VENDOR_ATTR_STA_INFO_TX_BYTES64, w->tx_bytes);
    nla_put_u64(m, RDK_VENDOR_ATTR_STA_INFO_RX_BYTES64, 123456 + idx);
    nla_put_u32(m, RDK_VENDOR_ATTR_STA_INFO_AUTH_FAILS, 2);
    nla_put_u64(m, RDK_VENDOR_ATTR_STA_INFO_ASSOC_NUM, 4);
    nla_put_u64(m, RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS64, w->tx_pkts);
    nla_put_u64(m, RDK_VENDOR_ATTR_STA_INFO_RX_PACKETS64, 888);
    nla_put_u64(m, RDK_VENDOR_ATTR_STA_INFO_TX_ERRORS, 9);
    nla_put_u64(m, RDK_VENDOR_ATTR_STA_INFO_TX_RETRANSMIT, 11);
    nla_put_u64(m, RDK_VENDOR_ATTR_STA_INFO_TX_FAILED_RETRIES, w->failed);
    nla_put_u64(m, RDK_VENDOR_ATTR_STA_INFO_TX_RETRIES, 13);
    nla_put_u64(m, RDK_VENDOR_ATTR_STA_INFO_TX_MULT_RETRIES, 14);
    nla_put_u32(m, RDK_VENDOR_ATTR_STA_INFO_TX_RATE_MAX, 1200);
    nla_put_u32(m, RDK_VENDOR_ATTR_STA_INFO_RX_RATE_MAX, 600);
    nla_put_u8(m, RDK_VENDOR_ATTR_STA_INFO_SPATIAL_STREAM_NUM, 2);
    nla_put_u8(m, RDK_VENDOR_ATTR_STA_INFO_ACTIVE_SPATIAL_STREAM_NUM, 1);
    nla_put_u64(m, RDK_VENDOR_ATTR_STA_INFO_TX_FRAMES, 500);
    nla_put_u64(m, RDK_VENDOR_ATTR_STA_INFO_RX_RETRIES, 6);
    nla_put_u64(m, RDK_VENDOR_ATTR_STA_INFO_RX_ERRORS, 8);
    if (w->mld >= 0) nla_put_u8(m, RDK_VENDOR_ATTR_STA_INFO_MLD_ENAB, (uint8_t)w->mld);
    if (w->mld_mac_len > 0) {
        unsigned char buf[4096]; int n = w->mld_mac_len > 4096 ? 4096 : w->mld_mac_len;
        memset(buf, 0xE0, sizeof(buf)); for (int k = 0; k < 6 && k < n; k++) buf[k] = 0xB0 + k;
        nla_put(m, RDK_VENDOR_ATTR_STA_INFO_MLD_MAC, n, buf);
    }
    nla_put_u8(m, RDK_VENDOR_ATTR_STA_INFO_POWER_SAVE, 1);
    nla_put_u64(m, RDK_VENDOR_ATTR_STA_INFO_PS_SLEEP_TIME_MS, 77);
    nla_nest_end(m, nest);
}

static struct nl_msg *build_reply(bga_world_t *w, int is_list, int idx)
{
    struct nl_msg *m = nlmsg_alloc_size(65536), *ex;
    struct nlattr *v;

    genlmsg_put(m, 0, 0, 0, 0, 0, NL80211_CMD_VENDOR, 0);
    if (!is_list && w->omit == 3) goto done;
    v = nla_nest_start(m, NL80211_ATTR_VENDOR_DATA);
    if (is_list) {
        int entries = w->list_entries < 0 ? w->nsta : w->list_entries;
        struct nlattr *lst;

        nla_put_u32(m, RDK_VENDOR_ATTR_STA_NUM, (uint32_t)(w->sta_num < 0 ? w->nsta : w->sta_num));
        lst = nla_nest_start(m, RDK_VENDOR_ATTR_STA_LIST);
        for (int i = 0; i < entries; i++) {
            unsigned char buf[16]; memset(buf, 0xEE, sizeof(buf)); memcpy(buf, w->mac[i & (BGA_MAXS - 1)], 6);
            nla_put(m, i + 1, w->list_mac_len, buf);
        }
        nla_nest_end(m, lst);
    } else {
        unsigned char buf[4096]; int n = w->mac_len > 4096 ? 4096 : w->mac_len;

        memset(buf, 0xEE, sizeof(buf)); memcpy(buf, w->mac[idx], 6);
        if (w->omit != 1) nla_put(m, RDK_VENDOR_ATTR_MAC, n, buf);
        if (w->omit != 2) put_info(m, w, idx);
    }
    nla_nest_end(m, v);
done:
    ex = nlmsg_convert(nlmsg_hdr(m));
    nlmsg_free(m);
    return ex;
}

static int nl80211_send_and_recv(struct nl_msg *msg, int (*valid_handler)(struct nl_msg *, void *), void *valid_data,
    int (*valid_finish_handler)(struct nl_msg *, void *), void *valid_finish_data)
{
    bga_world_t *w = &hwr_bga_world;
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct genlmsghdr *g = (struct genlmsghdr *)nlmsg_data(nlh);
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    int rc = 0;

    (void)valid_finish_handler; (void)valid_finish_data;
    w->send_calls++;
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(g, 0), genlmsg_attrlen(g, 0), NULL);
    if (tb[NL80211_ATTR_VENDOR_SUBCMD] && nla_get_u32(tb[NL80211_ATTR_VENDOR_SUBCMD]) == RDK_VENDOR_NL80211_SUBCMD_GET_STATION_LIST) {
        struct nl_msg *r = build_reply(w, 1, 0);
        valid_handler(r, valid_data);
        nlmsg_free(r);
        rc = w->dump_rc;
    } else {
        struct nlattr *tv[RDK_VENDOR_ATTR_MAX + 1];
        int idx = -1;

        if (tb[NL80211_ATTR_VENDOR_DATA] && nla_parse(tv, RDK_VENDOR_ATTR_MAX, nla_data(tb[NL80211_ATTR_VENDOR_DATA]), nla_len(tb[NL80211_ATTR_VENDOR_DATA]), NULL) >= 0 &&
            tv[RDK_VENDOR_ATTR_MAC]) {
            for (int i = 0; i < w->nsta; i++) if (memcmp(w->mac[i], nla_data(tv[RDK_VENDOR_ATTR_MAC]), 6) == 0) { idx = i; break; }
        }
        if (idx < 0 || idx == w->stats_fail_idx) {
            rc = -1;
        } else {
            struct nl_msg *r = build_reply(w, 0, idx);
            valid_handler(r, valid_data);
            nlmsg_free(r);
            rc = w->stats_rc;
        }
    }
    nlmsg_free(msg);
    return rc;
}

/* --- platform.c:3502-3973 --- */
typedef struct sta_list {
    mac_address_t *macs;
    unsigned int num;
} sta_list_t;

static int get_sta_list_handler(struct nl_msg *msg, void *arg)
{
    int rem_mac, i;
    struct nlattr *nlattr;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *tb_vendor[RDK_VENDOR_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    static struct nla_policy sta_policy[RDK_VENDOR_ATTR_MAX + 1] = {
        [RDK_VENDOR_ATTR_MAC] = { .type = NLA_BINARY },
        [RDK_VENDOR_ATTR_STA_NUM] = { .type = NLA_U32 },
        [RDK_VENDOR_ATTR_STA_LIST] = { .type = NLA_NESTED },
    };
    sta_list_t *sta_list = arg;

    if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0),
        NULL) < 0) {
        wifi_hal_stats_error_print("%s:%d Failed to parse vendor data\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (tb[NL80211_ATTR_VENDOR_DATA] == NULL) {
        wifi_hal_stats_error_print("%s:%d Vendor data is missing\n", __func__, __LINE__);
        return NL_SKIP;
    }

    nlattr = tb[NL80211_ATTR_VENDOR_DATA];
    if (nla_parse(tb_vendor, RDK_VENDOR_ATTR_MAX, nla_data(nlattr), nla_len(nlattr),
        sta_policy) < 0) {
        wifi_hal_stats_error_print("%s:%d Failed to parse vendor attribute\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (tb_vendor[RDK_VENDOR_ATTR_STA_NUM] == NULL) {
        wifi_hal_stats_error_print("%s:%d STA number data is missing\n", __func__, __LINE__);
        return NL_SKIP;
    }

    sta_list->num = nla_get_u32(tb_vendor[RDK_VENDOR_ATTR_STA_NUM]);
    if (sta_list->num == 0) {
        sta_list->macs = NULL;
        return NL_SKIP;
    }

    sta_list->macs = calloc(sta_list->num, sizeof(mac_address_t));
    if (sta_list->macs == NULL) {
        wifi_hal_stats_error_print("%s:%d Memory allocation failed\n", __func__, __LINE__);
        goto error;
    }
    if (tb_vendor[RDK_VENDOR_ATTR_STA_LIST] == NULL) {
        wifi_hal_stats_error_print("%s:%d STA list data is missing\n", __func__, __LINE__);
        goto error;
    }

    i = 0;
    nla_for_each_nested(nlattr, tb_vendor[RDK_VENDOR_ATTR_STA_LIST], rem_mac) {
        if (i >= sta_list->num) {
            wifi_hal_stats_error_print("%s:%d STA list overflow\n", __func__, __LINE__);
            goto error;
        }

        if (nla_len(nlattr) != sizeof(mac_address_t)) {
            wifi_hal_stats_error_print("%s:%d Wrong MAC address len\n", __func__, __LINE__);
            goto error;
        }

        memcpy(sta_list->macs[i], nla_data(nlattr), sizeof(mac_address_t));

        i++;
    }

    if (i != sta_list->num) {
        wifi_hal_stats_error_print("%s:%d Failed to receive all stations\n", __func__, __LINE__);
        goto error;
    }

    return NL_SKIP;

error:
    if (sta_list->macs != NULL) {
        free(sta_list->macs);
        sta_list->macs = NULL;
    }
    sta_list->num = 0;
    return NL_SKIP;
}

static int get_sta_list(wifi_interface_info_t *interface, sta_list_t *sta_list)
{
    int ret;
    struct nl_msg *msg;

    msg = nl80211_drv_vendor_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, OUI_COMCAST,
        RDK_VENDOR_NL80211_SUBCMD_GET_STATION_LIST);
    if (msg == NULL) {
        wifi_hal_stats_error_print("%s:%d Failed to create NL command\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    ret = nl80211_send_and_recv(msg, get_sta_list_handler, sta_list, NULL, NULL);
    if (ret) {
        wifi_hal_stats_error_print("%s:%d Failed to send NL message\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

static int standard_to_str(uint32_t standard, char *buf, size_t buf_size)
{
    char *std_str;

    switch (standard) {
        case RDK_VENDOR_NL80211_STANDARD_A: std_str = "a"; break;
        case RDK_VENDOR_NL80211_STANDARD_B: std_str = "b"; break;
        case RDK_VENDOR_NL80211_STANDARD_G: std_str = "g"; break;
        case RDK_VENDOR_NL80211_STANDARD_N: std_str = "n"; break;
        case RDK_VENDOR_NL80211_STANDARD_AC: std_str = "ac"; break;
        case RDK_VENDOR_NL80211_STANDARD_AD: std_str = "ad"; break;
        case RDK_VENDOR_NL80211_STANDARD_AX: std_str = "ax"; break;
#ifdef CONFIG_IEEE80211BE
        case RDK_VENDOR_NL80211_STANDARD_BE: std_str = "be"; break;
#endif /* CONFIG_IEEE80211BE */
        default: std_str = ""; break;
    }

    strncpy(buf, std_str, buf_size - 1);

    return 0;
}

static int bw_to_str(uint8_t bw, char *buf, size_t buf_size)
{
    char *bw_str;

    switch (bw) {
        case RDK_VENDOR_NL80211_CHAN_WIDTH_20: bw_str = "20"; break;
        case RDK_VENDOR_NL80211_CHAN_WIDTH_40: bw_str = "40"; break;
        case RDK_VENDOR_NL80211_CHAN_WIDTH_80: bw_str = "80"; break;
        case RDK_VENDOR_NL80211_CHAN_WIDTH_160: bw_str = "160"; break;
#ifdef CONFIG_IEEE80211BE
        case RDK_VENDOR_NL80211_CHAN_WIDTH_320: bw_str = "320"; break;
#endif /* CONFIG_IEEE80211BE */
        default: bw_str = ""; break;
    }

    strncpy(buf, bw_str, buf_size - 1);

    return 0;
}

static int get_sta_stats_handler(struct nl_msg *msg, void *arg)
{
    int i;
    struct nlattr *nlattr;
    struct nl80211_sta_flag_update *sta_flags;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *tb_vendor[RDK_VENDOR_ATTR_MAX + 1];
    struct nlattr *tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    static struct nla_policy vendor_policy[RDK_VENDOR_ATTR_MAX + 1] = {
        [RDK_VENDOR_ATTR_MAC] = { .type = NLA_BINARY, .minlen = ETHER_ADDR_LEN },
        [RDK_VENDOR_ATTR_STA_INFO] = { .type = NLA_NESTED },
    };
    static struct nla_policy sta_info_policy[RDK_VENDOR_ATTR_STA_INFO_MAX + 1] = {
        [RDK_VENDOR_ATTR_STA_INFO_STA_FLAGS] = { .type = NLA_BINARY,
            .minlen = sizeof(struct nl80211_sta_flag_update) },
        [RDK_VENDOR_ATTR_STA_INFO_RX_BITRATE_LAST] = { .type = NLA_U32 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_BITRATE_LAST] = { .type = NLA_U32 },
        [RDK_VENDOR_ATTR_STA_INFO_SIGNAL_AVG] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_RETRIES_PERCENT] = { .type = NLA_U32 },
        [RDK_VENDOR_ATTR_STA_INFO_ACTIVE] = { .type = NLA_U8 },
        [RDK_VENDOR_ATTR_STA_INFO_OPER_STANDARD] = { .type = NLA_U32 },
        [RDK_VENDOR_ATTR_STA_INFO_OPER_CHANNEL_BW] = { .type = NLA_U8 },
        [RDK_VENDOR_ATTR_STA_INFO_SNR] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS_ACK] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS_NO_ACK] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_BYTES64] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_RX_BYTES64] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_SIGNAL_MIN] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_STA_INFO_SIGNAL_MAX] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_STA_INFO_ASSOC_NUM] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS64] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_RX_PACKETS64] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_ERRORS] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_RETRANSMIT] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_FAILED_RETRIES] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_RETRIES] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_MULT_RETRIES] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_RATE_MAX] = { .type = NLA_U32 },
        [RDK_VENDOR_ATTR_STA_INFO_RX_RATE_MAX] = { .type = NLA_U32 },
        [RDK_VENDOR_ATTR_STA_INFO_SPATIAL_STREAM_NUM] = { .type = NLA_U8 },
        [RDK_VENDOR_ATTR_STA_INFO_ACTIVE_SPATIAL_STREAM_NUM] = { .type = NLA_U8 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_FRAMES] = {.type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_RX_RETRIES] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_RX_ERRORS] = {. type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_MLD_MAC] = {.type = NLA_BINARY, .minlen = ETHER_ADDR_LEN},
        [RDK_VENDOR_ATTR_STA_INFO_MLD_ENAB] = {.type = NLA_U8},
        [RDK_VENDOR_ATTR_STA_INFO_POWER_SAVE] = {.type = NLA_U8},
        [RDK_VENDOR_ATTR_STA_INFO_PS_SLEEP_TIME_MS] = {.type = NLA_U64},
    };
    wifi_associated_dev3_t *stats = arg;

    if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0),
        NULL) < 0) {
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
            wifi_hal_stats_error_print("%s:%d Vendor attribute %d is missing\n", __func__,
                __LINE__, i);
            return NL_SKIP;
        }
    }

    /* start fix 3 */
    memcpy(stats->cli_MACAddress, nla_data(tb_vendor[RDK_VENDOR_ATTR_MAC]),
        nla_len(tb_vendor[RDK_VENDOR_ATTR_MAC]) < sizeof(stats->cli_MACAddress) ?
        nla_len(tb_vendor[RDK_VENDOR_ATTR_MAC]) : sizeof(stats->cli_MACAddress));
    /* end fix 3 */

    if (nla_parse_nested(tb_sta_info, RDK_VENDOR_ATTR_STA_INFO_MAX,
        tb_vendor[RDK_VENDOR_ATTR_STA_INFO], sta_info_policy)) {
        wifi_hal_stats_error_print("%s:%d Failed to parse sta info attribute\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_STA_FLAGS]) {
        sta_flags = nla_data(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_STA_FLAGS]);
        stats->cli_AuthenticationState = sta_flags->mask & (1 << NL80211_STA_FLAG_AUTHORIZED) &&
            sta_flags->set & (1 << NL80211_STA_FLAG_AUTHORIZED);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_BITRATE_LAST]) {
        stats->cli_LastDataUplinkRate =
            nla_get_u32(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_BITRATE_LAST]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_BITRATE_LAST]) {
        stats->cli_LastDataDownlinkRate =
            nla_get_u32(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_BITRATE_LAST]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_SIGNAL_AVG]) {
        stats->cli_RSSI = nla_get_s32(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_SIGNAL_AVG]);
        stats->cli_SignalStrength = stats->cli_RSSI;
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_SIGNAL_MIN]) {
        stats->cli_MinRSSI = nla_get_s32(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_SIGNAL_MIN]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_SIGNAL_MAX]) {
        stats->cli_MaxRSSI = nla_get_s32(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_SIGNAL_MAX]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_RETRIES_PERCENT]) {
        stats->cli_Retransmissions =
            nla_get_u32(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_RETRIES_PERCENT]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_ACTIVE]) {
        stats->cli_Active = nla_get_u8(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_ACTIVE]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_OPER_STANDARD]) {
        standard_to_str(nla_get_u32(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_OPER_STANDARD]),
            stats->cli_OperatingStandard, sizeof(stats->cli_OperatingStandard));
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_OPER_CHANNEL_BW]) {
        bw_to_str(nla_get_u8(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_OPER_CHANNEL_BW]),
            stats->cli_OperatingChannelBandwidth, sizeof(stats->cli_OperatingChannelBandwidth));
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_SNR]) {
        stats->cli_SNR = nla_get_s32(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_SNR]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS_ACK]) {
        stats->cli_DataFramesSentAck =
            nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS_ACK]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS_NO_ACK]) {
        stats->cli_DataFramesSentNoAck =
            nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS_NO_ACK]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_BYTES64]) {
        stats->cli_BytesSent = nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_BYTES64]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_BYTES64]) {
        stats->cli_BytesReceived = nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_BYTES64]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_AUTH_FAILS]) {
        stats->cli_AuthenticationFailures =
            nla_get_u32(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_AUTH_FAILS]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_ASSOC_NUM]) {
        stats->cli_Associations = nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_ASSOC_NUM]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS64]) {
        stats->cli_PacketsSent = nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS64]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_PACKETS64]) {
        stats->cli_PacketsReceived =
            nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_PACKETS64]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_ERRORS]) {
        stats->cli_ErrorsSent =
            nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_ERRORS]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_RETRANSMIT]) {
        stats->cli_RetransCount =
            nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_RETRANSMIT]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_FAILED_RETRIES]) {
        stats->cli_FailedRetransCount =
            nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_FAILED_RETRIES]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_RETRIES]) {
        stats->cli_RetryCount = nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_RETRIES]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_MULT_RETRIES]) {
        stats->cli_MultipleRetryCount =
            nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_MULT_RETRIES]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_RATE_MAX]) {
        stats->cli_MaxDownlinkRate =
            nla_get_u32(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_RATE_MAX]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_RATE_MAX]) {
        stats->cli_MaxUplinkRate =
            nla_get_u32(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_RATE_MAX]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_SPATIAL_STREAM_NUM]) {
        stats->cli_capableNumSpatialStreams =
            nla_get_u8(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_SPATIAL_STREAM_NUM]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_ACTIVE_SPATIAL_STREAM_NUM]) {
        stats->cli_activeNumSpatialStreams =
            nla_get_u8(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_ACTIVE_SPATIAL_STREAM_NUM]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_FRAMES]) {
        stats->cli_TxFrames = nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_FRAMES]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_RETRIES]) {
        stats->cli_RxRetries = nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_RETRIES]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_ERRORS]) {
        stats->cli_RxErrors = nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_ERRORS]);
    }

    if(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_MLD_ENAB]) {
        stats->cli_MLDEnable = nla_get_u8(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_MLD_ENAB]);
    } else {
        stats->cli_MLDEnable = 0;
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_MLD_MAC]) {
        /* start fix 4 */
        memcpy(stats->cli_MLDAddr, nla_data(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_MLD_MAC]),
               nla_len(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_MLD_MAC]) < sizeof(stats->cli_MLDAddr) ?
               nla_len(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_MLD_MAC]) : sizeof(stats->cli_MLDAddr));
        /* end fix 4 */
    } else {
        memset(stats->cli_MLDAddr, 0, sizeof(stats->cli_MLDAddr));
    }
    
    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_POWER_SAVE]) {
        stats->cli_PowerSaveMode = nla_get_u8(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_POWER_SAVE]);
    } else {
        stats->cli_PowerSaveMode = 0;
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_PS_SLEEP_TIME_MS]) {
        stats->cli_sleepTime = nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_PS_SLEEP_TIME_MS]);
    } else {
        stats->cli_sleepTime = 0;
    }


    wifi_hal_stats_dbg_print("%s:%d cli_DataFramesSentAck: %lu cli_DataFramesSentNoAck: %lu cli_PacketsSent: %lu cli_BytesSent: %lu activeNumSpatialStreams: %u cli_capableNumSpatialStreams: %u\n", __func__, __LINE__, 
            stats->cli_DataFramesSentAck, stats->cli_DataFramesSentNoAck,
           stats->cli_PacketsSent, stats->cli_BytesSent, stats->cli_activeNumSpatialStreams, stats->cli_capableNumSpatialStreams);

    /*
     * Assume the default packet size for wifi blaster is 1470
     * Sometimes when the AP is just up, the cli_BytesSent
     * is very low as just a couple of frames have been sent and not real data.
     * In this case (cli_BytesSent / WIFI_BLASTER_DEFAULT_PKTSIZE)
     * will be 1 or 2 or another low value which is in fact lower than
     * cli_PacketsSent.
     */

    stats->cli_DataFramesSentNoAck = stats->cli_FailedRetransCount;
    if (((stats->cli_BytesSent / WIFI_BLASTER_DEFAULT_PKTSIZE) < stats->cli_PacketsSent)) {
        stats->cli_DataFramesSentAck = stats->cli_PacketsSent - stats->cli_DataFramesSentNoAck;
    } else {
        stats->cli_DataFramesSentAck = (stats->cli_BytesSent / WIFI_BLASTER_DEFAULT_PKTSIZE) -
                          stats->cli_DataFramesSentNoAck;
    }
    stats->cli_PacketsSent = stats->cli_DataFramesSentAck + stats->cli_DataFramesSentNoAck;

    wifi_hal_stats_dbg_print("%s:%d cli_DataFramesSentAck: %lu cli_DataFramesSentNoAck: %lu cli_PacketsSent: %lu cli_BytesSent: %lu cli_PowerSaveMode=%d cli_sleepTime: %lu\n", __func__, __LINE__, 
            stats->cli_DataFramesSentAck, stats->cli_DataFramesSentNoAck,
            stats->cli_PacketsSent, stats->cli_BytesSent, stats->cli_PowerSaveMode,stats->cli_sleepTime);

    return NL_SKIP;
}

static int get_sta_stats(wifi_interface_info_t *interface, mac_address_t mac,
    wifi_associated_dev3_t *stats)
{
    struct nl_msg *msg;
    struct nlattr *nlattr;
    int ret = RETURN_ERR;

    msg = nl80211_drv_vendor_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, OUI_COMCAST,
        RDK_VENDOR_NL80211_SUBCMD_GET_STATION);
    if (msg == NULL) {
        wifi_hal_stats_error_print("%s:%d Failed to create NL command\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    nlattr = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
    if (nla_put(msg, RDK_VENDOR_ATTR_MAC, ETHER_ADDR_LEN, mac) < 0) {
        wifi_hal_stats_error_print("%s:%d Failed to put mac address\n", __func__, __LINE__);
        nlmsg_free(msg);
        return RETURN_ERR;
    }
    nla_nest_end(msg, nlattr);

    ret = nl80211_send_and_recv(msg, get_sta_stats_handler, stats, NULL, NULL);
    if (ret) {
        wifi_hal_stats_error_print("%s:%d Failed to send NL message\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    return ret;
}


/* --- platform.c:3974-4013 --- */
INT wifi_getApAssociatedDeviceDiagnosticResult3(INT apIndex,
    wifi_associated_dev3_t **associated_dev_array, UINT *output_array_size)
{
    int ret;
    unsigned int i;
    sta_list_t sta_list = {};
    wifi_interface_info_t *interface;

    /* start fix 1 */
    if (associated_dev_array == NULL || output_array_size == NULL) {
        wifi_hal_stats_error_print("%s:%d NULL output argument\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    /* end fix 1 */

    interface = get_interface_by_vap_index(apIndex);
    if (interface == NULL) {
        wifi_hal_stats_error_print("%s:%d Failed to get interface for index %d\n", __func__, __LINE__,
            apIndex);
        return RETURN_ERR;
    }

    ret = get_sta_list(interface, &sta_list);
    if (ret != RETURN_OK) {
        wifi_hal_stats_error_print("%s:%d Failed to get sta list\n", __func__, __LINE__);
        goto exit;
    }

    *associated_dev_array = sta_list.num ?
        calloc(sta_list.num, sizeof(wifi_associated_dev3_t)) : NULL;
    /* start fix 2 */
    if (sta_list.num && *associated_dev_array == NULL) {
        wifi_hal_stats_error_print("%s:%d calloc failed\n", __func__, __LINE__);
        *output_array_size = 0;
        ret = RETURN_ERR;
        goto exit;
    }
    /* end fix 2 */
    *output_array_size = sta_list.num;

    for (i = 0; i < sta_list.num; i++) {
        ret = get_sta_stats(interface, sta_list.macs[i], &(*associated_dev_array)[i]);
        if (ret != RETURN_OK) {
            wifi_hal_stats_error_print("%s:%d Failed to get sta stats\n", __func__, __LINE__);
            free(*associated_dev_array);
            *associated_dev_array = NULL;
            *output_array_size = 0;
            goto exit;
        }
    }

exit:
    free(sta_list.macs);
    return ret;
}
