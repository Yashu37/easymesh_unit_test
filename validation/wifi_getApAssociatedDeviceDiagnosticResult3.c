/*
 * HANDLER: wifi_getApAssociatedDeviceDiagnosticResult3
 *
 * Functions copied VERBATIM from rdk-wifi-hal (~/Desktop/G/rdk-wifi-hal): platform/banana-pi/platform.c:682-906 - get_sta_list_handler, get_sta_list,
 * set_wifi_standard_from_rate, get_sta_stats_handler, get_sta_stats and wifi_getApAssociatedDeviceDiagnosticResult3 - and the sta_list_t type
 * (platform.c, just above wifi_nvram_defaultRead).  This file holds the FIXED code: every change sits between "start fix n" / "end fix n" markers (the unfixed copy is the reproducer commit).  The netlink handlers are the REAL ones,
 * running on real libnl messages.  This file is compiled as C (the verbatim code uses out-of-order designated initializers, which C++ rejects).
 *
 * Scaffolding only (the real types need the hostap / driver header tree, see hwr_gad.h):
 *  - nl80211_drv_cmd_msg (wifi_hal_nl80211.c:4061): the real body over a plain interface (index / phy_index); the runner can make it fail.
 *  - nl80211_send_and_recv (wifi_hal_nl80211.c:3905): the "kernel".  For the NLM_F_DUMP station dump it calls the handler once per station with a
 *    NEW_STATION message holding the MAC attribute; for a GET_STATION query it finds the MAC attribute in the request, looks the station up
 *    and calls the handler with a reply holding the MAC and a STA_INFO nest of the statistics of the station's template.  Every reply is copied
 *    into an exact-size heap block (nlmsg_convert), so a read behind the message is an ASan overflow.  The request is freed like the real one.
 *  - get_interface_by_vap_index: runner-controlled lookup.  calloc / realloc / free over counting wrappers (live blocks; the runner can make
 *    calloc or the n-th realloc fail).  The print macros are mapped to the log sink hwr_print (runner-poisoned slot).
 *  - BPI_LEN_64 and the wifi_associated_dev3_t / mac_address_t types are the real ones.
 */
#include "hwr_gad.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define wifi_hal_stats_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)        hwr_print(1, format, ##__VA_ARGS__)
#define BPI_LEN_64 64
#define wifi_interface_info_t gad_interface_t
#define wifi_getApAssociatedDeviceDiagnosticResult3 hwr_wifi_getApAssociatedDeviceDiagnosticResult3

gad_world_t hwr_gad_world;
static struct { int nl80211_id; } g_wifi_hal = { 28 };

static gad_interface_t *get_interface_by_vap_index(unsigned int vap_index)
{
    return (hwr_gad_world.iface && hwr_gad_world.iface->vap_index == vap_index) ? hwr_gad_world.iface : NULL;
}

/* allocation the runner can make fail, and count of live blocks */
static void *gad_calloc(size_t n, size_t s)
{
    hwr_gad_world.calloc_calls++;
    if (hwr_gad_world.fail_calloc) return NULL;
    void *p = calloc(n, s); if (p) hwr_gad_world.live++; return p;
}
static void *gad_realloc(void *old, size_t s)
{
    hwr_gad_world.realloc_calls++;
    if (hwr_gad_world.fail_realloc_at && hwr_gad_world.realloc_calls == hwr_gad_world.fail_realloc_at) return NULL;
    void *p = realloc(old, s); if (p && !old) hwr_gad_world.live++; return p;
}
static void gad_free(void *p) { if (p) hwr_gad_world.live--; free(p); }
#define calloc  gad_calloc
#define realloc gad_realloc
#define free    gad_free

/* --- wifi_hal_nl80211.c:4061 --- */
static struct nl_msg *nl80211_drv_cmd_msg(int nl80211_id, wifi_interface_info_t *intf, int flags, uint8_t cmd)
{
    struct nl_msg *msg;

    hwr_gad_world.cmd_calls++;
    if ((flags & NLM_F_DUMP) ? hwr_gad_world.list_cmd_fail : hwr_gad_world.stats_cmd_fail) return NULL;
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

/* a reply of the "kernel": exact-size heap copy of the message */
static struct nl_msg *build_reply(int mac_len, const unsigned char *mac, int tmpl)
{
    struct nl_msg *m = nlmsg_alloc(), *ex;
    struct nlattr *nest, *rate;

    genlmsg_put(m, 0, 0, 0, 0, 0, NL80211_CMD_NEW_STATION, 0);
    if (mac_len > 0) nla_put(m, NL80211_ATTR_MAC, mac_len, mac);
    if (tmpl >= 0) {
        const gad_tmpl_t *t = &gad_tmpl[tmpl];
        nest = nla_nest_start(m, NL80211_ATTR_STA_INFO);
        if (!t->empty_info) {
            nla_put_u32(m, NL80211_STA_INFO_RX_BYTES, t->rx_bytes);
            nla_put_u32(m, NL80211_STA_INFO_TX_BYTES, t->tx_bytes);
            nla_put_u32(m, NL80211_STA_INFO_RX_PACKETS, t->rx_pkts);
            nla_put_u32(m, NL80211_STA_INFO_TX_PACKETS, t->tx_pkts);
            nla_put_u32(m, NL80211_STA_INFO_TX_FAILED, t->tx_failed);
            nla_put_u32(m, NL80211_STA_INFO_TX_RETRIES, t->retries);
            nla_put_u64(m, NL80211_STA_INFO_RX_DROP_MISC, t->rx_drop);
            if (t->signal) nla_put_u8(m, NL80211_STA_INFO_SIGNAL, (unsigned char)t->signal);
            if (t->tx_kind) {
                rate = nla_nest_start(m, NL80211_STA_INFO_TX_BITRATE);
                if (t->tx_br32) nla_put_u32(m, NL80211_RATE_INFO_BITRATE32, t->tx_br32);
                if (t->tx_kind == 1) nla_put_flag(m, NL80211_RATE_INFO_HE_MCS);
                if (t->tx_kind == 2) nla_put_flag(m, NL80211_RATE_INFO_VHT_MCS);
                if (t->tx_kind == 3) nla_put_flag(m, NL80211_RATE_INFO_MCS);
                nla_nest_end(m, rate);
            }
            if (t->rx_kind) {
                rate = nla_nest_start(m, NL80211_STA_INFO_RX_BITRATE);
                if (t->rx_br32) nla_put_u32(m, NL80211_RATE_INFO_BITRATE32, t->rx_br32);
                if (t->rx_kind == 1) nla_put_flag(m, NL80211_RATE_INFO_HE_MCS);
                if (t->rx_kind == 2) nla_put_flag(m, NL80211_RATE_INFO_VHT_MCS);
                if (t->rx_kind == 3) nla_put_flag(m, NL80211_RATE_INFO_MCS);
                nla_nest_end(m, rate);
            }
            if (t->flags_mode) {
                struct nl80211_sta_flag_update fl; memset(&fl, 0, sizeof(fl));
                fl.mask = (1 << NL80211_STA_FLAG_AUTHORIZED) | (1 << NL80211_STA_FLAG_WME);
                fl.set  = (t->flags_mode == 1 ? (1 << NL80211_STA_FLAG_AUTHORIZED) : 0) | (1 << NL80211_STA_FLAG_WME);
                nla_put(m, NL80211_STA_INFO_STA_FLAGS, sizeof(fl), &fl);
            }
        }
        nla_nest_end(m, nest);
    }
    ex = nlmsg_convert(nlmsg_hdr(m));
    nlmsg_free(m);
    return ex;
}

/* --- wifi_hal_nl80211.c:3905 (the kernel side) --- */
static int nl80211_send_and_recv(struct nl_msg *msg, int (*valid_handler)(struct nl_msg *, void *), void *valid_data,
    int (*valid_finish_handler)(struct nl_msg *, void *), void *valid_finish_data)
{
    gad_world_t *w = &hwr_gad_world;
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct genlmsghdr *g = (struct genlmsghdr *)nlmsg_data(nlh);
    int rc = 0;

    (void)valid_finish_handler; (void)valid_finish_data;
    w->send_calls++;
    if (nlh->nlmsg_flags & NLM_F_DUMP) {
        for (int i = 0; i < w->nsta; i++) {
            int mlen = (w->quirk == 1 && i == 0) ? 2 : (w->quirk == 2 && i == 0) ? 0 : 6;
            struct nl_msg *r = build_reply(mlen, w->sta[i].mac, -1);
            valid_handler(r, valid_data);
            nlmsg_free(r);
        }
        rc = w->dump_rc;
    } else {
        struct nlattr *tb[NL80211_ATTR_MAX + 1];
        int idx = -1;

        if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(g, 0), genlmsg_attrlen(g, 0), NULL) >= 0 && tb[NL80211_ATTR_MAC]) {
            for (int i = 0; i < w->nsta; i++) if (memcmp(w->sta[i].mac, nla_data(tb[NL80211_ATTR_MAC]), 6) == 0) { idx = i; break; }
        }
        if (idx < 0 || idx == w->stats_fail_idx) {
            rc = -1;                               /* the kernel has no such station / the query fails */
        } else {
            struct nl_msg *r = build_reply((w->quirk == 3 && idx == 0) ? 2 : 6, w->sta[idx].mac, w->sta[idx].tmpl);
            valid_handler(r, valid_data);
            nlmsg_free(r);
        }
    }
    nlmsg_free(msg);
    return rc;
}

/* --- platform.c:50-53 --- */
typedef struct {
    mac_address_t *macs;
    unsigned int num;
    /* start fix 3 */
    int failed;
    /* end fix 3 */
} sta_list_t;

/* --- platform.c:682-867 --- */
static int get_sta_list_handler(struct nl_msg *msg, void *arg)
{
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    sta_list_t *sta_list = (sta_list_t *)arg;

    if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0),
        NULL) < 0) {
        wifi_hal_stats_error_print("%s:%d Failed to parse sta data\n", __func__, __LINE__);
        return NL_SKIP;
    }

    /* start fix 4 */
    if (tb[NL80211_ATTR_MAC] && nla_len(tb[NL80211_ATTR_MAC]) >= (int)sizeof(mac_address_t)) {
    /* end fix 4 */
        /* start fix 3 */
        mac_address_t *grown = realloc(sta_list->macs, (sta_list->num + 1) * sizeof(mac_address_t));
        if (grown == NULL) {
            free(sta_list->macs);
            sta_list->macs = NULL;
            sta_list->num = 0;
            sta_list->failed = 1;
            return NL_STOP;
        }
        sta_list->macs = grown;
        /* end fix 3 */
        if (sta_list->macs) {
            memcpy(sta_list->macs[sta_list->num], nla_data(tb[NL80211_ATTR_MAC]), sizeof(mac_address_t));
            sta_list->num++;
        }
    }

    return NL_OK;
}

static int get_sta_list(wifi_interface_info_t *interface, sta_list_t *sta_list)
{
    int ret;
    struct nl_msg *msg = NULL;

    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, NLM_F_DUMP, NL80211_CMD_GET_STATION);
    if (msg == NULL) {
        wifi_hal_stats_error_print("%s:%d Failed to create NL command\n", __func__, __LINE__);
        return -1;
    }

    ret = nl80211_send_and_recv(msg, get_sta_list_handler, sta_list, NULL, NULL);
    if (ret < 0) {
        wifi_hal_stats_error_print("%s:%d Failed to execute NL command\n", __func__, __LINE__);
        return -1;
    }

    /* start fix 3 */
    if (sta_list->failed) {
        return -1;
    }
    /* end fix 3 */

    return 0;
}

static void set_wifi_standard_from_rate(struct nlattr **rate, char *cli_OperatingStandard)
{
#if defined(NL80211_RATE_INFO_EHT_MCS) && defined(CONFIG_IEEE80211BE)
    if (rate[NL80211_RATE_INFO_EHT_MCS]) {
        snprintf(cli_OperatingStandard, BPI_LEN_64, "be");
    } else
#endif
    if (rate[NL80211_RATE_INFO_HE_MCS]) {
        snprintf(cli_OperatingStandard, BPI_LEN_64, "ax");
    } else if (rate[NL80211_RATE_INFO_VHT_MCS]) {
        snprintf(cli_OperatingStandard, BPI_LEN_64, "ac");
    } else if (rate[NL80211_RATE_INFO_MCS]) {
        snprintf(cli_OperatingStandard, BPI_LEN_64, "n");
    } else {
        cli_OperatingStandard[0] = '\0';
    }
}

static int get_sta_stats_handler(struct nl_msg *msg, void *arg)
{
    wifi_associated_dev3_t *dev = (wifi_associated_dev3_t *)arg;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *stats[NL80211_STA_INFO_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
                [NL80211_STA_INFO_INACTIVE_TIME] = { .type = NLA_U32 },
                [NL80211_STA_INFO_RX_BYTES] = { .type = NLA_U32 },
                [NL80211_STA_INFO_TX_BYTES] = { .type = NLA_U32 },
                [NL80211_STA_INFO_RX_PACKETS] = { .type = NLA_U32 },
                [NL80211_STA_INFO_TX_PACKETS] = { .type = NLA_U32 },
                [NL80211_STA_INFO_TX_FAILED] = { .type = NLA_U32 },
                [NL80211_STA_INFO_TX_RETRIES] = { .type = NLA_U32 },
                [NL80211_STA_INFO_CONNECTED_TIME] = { .type = NLA_U32 },
                [NL80211_STA_INFO_TX_BITRATE] = { .type = NLA_NESTED },
                [NL80211_STA_INFO_RX_BITRATE] = { .type = NLA_NESTED },
                [NL80211_STA_INFO_STA_FLAGS] = { .minlen = sizeof(struct nl80211_sta_flag_update) },
                [NL80211_STA_INFO_RX_DROP_MISC] = { .type = NLA_U64 },
                [NL80211_STA_INFO_SIGNAL] = { .type = NLA_U8 },
    };
    struct nlattr *rate[NL80211_RATE_INFO_MAX + 1];
    static struct nla_policy rate_policy[NL80211_RATE_INFO_MAX + 1] = {
                [NL80211_RATE_INFO_BITRATE32] = { .type = NLA_U32 },
    };
    struct nl80211_sta_flag_update *sta_flags;

    if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),genlmsg_attrlen(gnlh, 0),
        NULL) < 0) {
        wifi_hal_error_print("%s:%d Failed to parse sta data\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (!tb[NL80211_ATTR_STA_INFO]) {
        wifi_hal_error_print("%s:%d Failed to get sta info attribute\n", __func__, __LINE__);
        return NL_SKIP;
    }

    /* start fix 4 */
    if (tb[NL80211_ATTR_MAC] && nla_len(tb[NL80211_ATTR_MAC]) >= (int)sizeof(mac_address_t)) {
    /* end fix 4 */
        memcpy(dev->cli_MACAddress, nla_data(tb[NL80211_ATTR_MAC]), sizeof(mac_address_t));
    }

    if (nla_parse_nested(stats, NL80211_STA_INFO_MAX, tb[NL80211_ATTR_STA_INFO], stats_policy)) {
	wifi_hal_error_print("%s:%d Failed to parse nested attributes\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (stats[NL80211_STA_INFO_RX_BYTES]) {
        dev->cli_BytesReceived = nla_get_u32(stats[NL80211_STA_INFO_RX_BYTES]);
    }
    if (stats[NL80211_STA_INFO_TX_BYTES]) {
        dev->cli_BytesSent = nla_get_u32(stats[NL80211_STA_INFO_TX_BYTES]);
    }
    if (stats[NL80211_STA_INFO_RX_PACKETS]) {
        dev->cli_PacketsReceived = nla_get_u32(stats[NL80211_STA_INFO_RX_PACKETS]);
    }
    if (stats[NL80211_STA_INFO_TX_PACKETS]) {
        dev->cli_PacketsSent = nla_get_u32(stats[NL80211_STA_INFO_TX_PACKETS]);
    }
    if (stats[NL80211_STA_INFO_TX_FAILED]) {
        dev->cli_ErrorsSent = nla_get_u32(stats[NL80211_STA_INFO_TX_FAILED]);
    }

    if (stats[NL80211_STA_INFO_RX_DROP_MISC]) {
        dev->cli_RxErrors = nla_get_u64(stats[NL80211_STA_INFO_RX_DROP_MISC]);
    }

    if (stats[NL80211_STA_INFO_TX_RETRIES]) {
        dev->cli_RetransCount = nla_get_u32(stats[NL80211_STA_INFO_TX_RETRIES]);
    }

    if (stats[NL80211_STA_INFO_SIGNAL]) {
        dev->cli_RSSI = (int8_t)nla_get_u8(stats[NL80211_STA_INFO_SIGNAL]);
    }

    if (stats[NL80211_STA_INFO_TX_BITRATE] &&
        nla_parse_nested(rate, NL80211_RATE_INFO_MAX, stats[NL80211_STA_INFO_TX_BITRATE], rate_policy) == 0) {
        if (rate[NL80211_RATE_INFO_BITRATE32]){
            dev->cli_LastDataDownlinkRate = nla_get_u32(rate[NL80211_RATE_INFO_BITRATE32]) * 100;
        }
        set_wifi_standard_from_rate(rate, dev->cli_OperatingStandard);
    }

    if (stats[NL80211_STA_INFO_RX_BITRATE] &&
        nla_parse_nested(rate, NL80211_RATE_INFO_MAX, stats[NL80211_STA_INFO_RX_BITRATE], rate_policy) == 0) {
        if (rate[NL80211_RATE_INFO_BITRATE32]) {
                dev->cli_LastDataUplinkRate = nla_get_u32(rate[NL80211_RATE_INFO_BITRATE32]) * 100;
        }
        // Wi-Fi Standard fallback from RX bitrate
        if (dev->cli_OperatingStandard[0] == '\0') {
            set_wifi_standard_from_rate(rate, dev->cli_OperatingStandard);
        }
    }

    if (stats[NL80211_STA_INFO_STA_FLAGS]) {
        sta_flags = nla_data(stats[NL80211_STA_INFO_STA_FLAGS]);
        dev->cli_AuthenticationState = sta_flags->mask & (1 << NL80211_STA_FLAG_AUTHORIZED) &&
            sta_flags->set & (1 << NL80211_STA_FLAG_AUTHORIZED);
    }

    return NL_OK;
}

static int get_sta_stats(wifi_interface_info_t *interface, mac_address_t mac, wifi_associated_dev3_t *dev)
{
    int ret;
    struct nl_msg *msg = NULL;

    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_GET_STATION);
    if (msg == NULL) {
        wifi_hal_error_print("%s:%d Failed to create NL command\n", __func__, __LINE__);
        return -1;
    }

    nla_put(msg, NL80211_ATTR_MAC, sizeof(mac_address_t), mac);

    ret = nl80211_send_and_recv(msg, get_sta_stats_handler, dev, NULL, NULL);
    if (ret < 0) {
        wifi_hal_error_print("%s:%d Failed to execute NL command\n", __func__, __LINE__);
        return -1;
    }

    return 0;
}


/* --- platform.c:868-906 --- */
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
        return -1;
    }
    /* end fix 1 */

    interface = get_interface_by_vap_index(apIndex);
    if (interface == NULL) {
        wifi_hal_stats_error_print("%s:%d Failed to get interface for index %d\n", __func__, __LINE__, apIndex);
        return -1;
    }

    ret = get_sta_list(interface, &sta_list);
    if (ret < 0) {
        wifi_hal_stats_error_print("%s:%d Failed to get sta list\n", __func__, __LINE__);
        goto exit;
    }

    *associated_dev_array = sta_list.num ?
        calloc(sta_list.num, sizeof(wifi_associated_dev3_t)) : NULL;
    *output_array_size = sta_list.num;

    /* start fix 2 */
    if (sta_list.num && *associated_dev_array == NULL) {
        wifi_hal_stats_error_print("%s:%d Failed to allocate %u entries\n", __func__, __LINE__, sta_list.num);
        *output_array_size = 0;
        ret = -1;
        goto exit;
    }
    /* end fix 2 */

    for (i = 0; i < sta_list.num; i++) {
        ret = get_sta_stats(interface, sta_list.macs[i], &(*associated_dev_array)[i]);
        if (ret < 0) {
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
