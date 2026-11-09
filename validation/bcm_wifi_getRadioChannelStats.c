/*
 * HANDLER: wifi_getRadioChannelStats (platform/broadcom)
 *
 * Functions copied VERBATIM from rdk-wifi-hal (~/Desktop/G/rdk-wifi-hal): platform/broadcom/platform.c:4015-4175 - get_channel_stats_handler,
 * get_channel_stats and wifi_getRadioChannelStats - together with the REAL ieee80211_freq_to_chan / ieee80211_freq_to_channel_ext from hostap-2.10
 * (ieee802_11_common.c).  This file holds the ORIGINAL code with fixes 1-2 applied (start fix n / end fix n markers; the unfixed copy is the reproducer).  The netlink handler is the REAL one, running on real libnl messages.
 * Compiled as C.
 *
 * Scaffolding only (the Broadcom vendor header rdk_nl80211_hal.h is not in the source tree, so the RDK_VENDOR_* numbers below are the harness's own):
 *  - nl80211_drv_vendor_cmd_msg / nl80211_drv_cmd_msg: the real bodies (wifi_hal_nl80211.c:4083 / 4061); the runner can make the command message NULL.
 *  - nl80211_send_and_recv: the "kernel": calls the handler once with a vendor-data nest holding RDK_VENDOR_ATTR_SURVEY_INFO and one nested survey entry
 *    per world entry (all 12 survey attributes, one of them optionally left out).  The reply is an exact-size heap block (nlmsg_convert); the request is
 *    freed like the real one.
 *  - get_radio_by_rdk_index / get_primary_interface: runner-controlled lookups.  The print macros map to the log sink hwr_print (runner-poisoned slot).
 */
#include "hwr_bgk.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define wifi_hal_stats_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define wifi_hal_stats_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_radio_info_t bgk_radio_t
#define wifi_interface_info_t bgk_iface_t
#define wifi_getRadioChannelStats hwr_bcm_wifi_getRadioChannelStats
#define OUI_COMCAST 0x001018

typedef unsigned char u8;
enum hostapd_hw_mode { HOSTAPD_MODE_IEEE80211B, HOSTAPD_MODE_IEEE80211G, HOSTAPD_MODE_IEEE80211A, HOSTAPD_MODE_IEEE80211AD, HOSTAPD_MODE_IEEE80211ANY, NUM_HOSTAPD_MODES };
#define CHANWIDTH_USE_HT	0
#define CHANWIDTH_80MHZ		1
#define CHANWIDTH_160MHZ	2
#define CHANWIDTH_80P80MHZ	3
#define CHANWIDTH_2160MHZ	4
#define CHANWIDTH_4320MHZ	5
#define CHANWIDTH_6480MHZ	6
#define CHANWIDTH_8640MHZ	7

enum { RDK_VENDOR_ATTR_INVALID, RDK_VENDOR_ATTR_SURVEY_INFO, RDK_VENDOR_ATTR_MAX = RDK_VENDOR_ATTR_SURVEY_INFO };
enum { RDK_VENDOR_ATTR_SURVEY_INFO_INVALID, RDK_VENDOR_ATTR_SURVEY_INFO_FREQUENCY, RDK_VENDOR_ATTR_SURVEY_INFO_NOISE, RDK_VENDOR_ATTR_SURVEY_INFO_RADAR_NOISE,
       RDK_VENDOR_ATTR_SURVEY_INFO_MAX_RSSI, RDK_VENDOR_ATTR_SURVEY_INFO_NON_80211_NOISE, RDK_VENDOR_ATTR_SURVEY_INFO_CHAN_UTIL,
       RDK_VENDOR_ATTR_SURVEY_INFO_TIME_ACTIVE, RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY, RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY_TX,
       RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY_RX, RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY_RX_SELF, RDK_VENDOR_ATTR_SURVEY_INFO_TIME_EXT_BUSY,
       RDK_VENDOR_ATTR_SURVEY_INFO_MAX = RDK_VENDOR_ATTR_SURVEY_INFO_TIME_EXT_BUSY };
enum { RDK_VENDOR_NL80211_SUBCMD_GET_SURVEY = 3 };

bgk_world_t hwr_bgk_world;
static struct { int nl80211_id; } g_wifi_hal = { 28 };

typedef struct {
    wifi_channelStats_t *arr;
    int arr_size;
}channel_stats_arr_t;

static bgk_radio_t *get_radio_by_rdk_index(int index)
{
    return (hwr_bgk_world.radio && hwr_bgk_world.radio->rdk_index == index) ? hwr_bgk_world.radio : NULL;
}
static bgk_iface_t *get_primary_interface(bgk_radio_t *radio) { return radio->primary; }

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

    hwr_bgk_world.cmd_calls++;
    if (hwr_bgk_world.cmd_fail) return NULL;
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
static struct nl_msg *build_reply(bgk_world_t *w)
{
    struct nl_msg *m = nlmsg_alloc_size(65536), *ex;

    genlmsg_put(m, 0, 0, 0, 0, 0, NL80211_CMD_VENDOR, 0);
    if (w->omit_reply != 1) {
        struct nlattr *v = nla_nest_start(m, NL80211_ATTR_VENDOR_DATA);
        if (w->omit_reply != 2) {
            struct nlattr *sv = nla_nest_start(m, RDK_VENDOR_ATTR_SURVEY_INFO);
            for (int k = 0; k < w->nent; k++) {
                struct nlattr *en = nla_nest_start(m, k + 1);
                int o = w->e[k].omit_attr;
                if (o != RDK_VENDOR_ATTR_SURVEY_INFO_FREQUENCY) nla_put_u32(m, RDK_VENDOR_ATTR_SURVEY_INFO_FREQUENCY, w->e[k].freq);
                if (o != RDK_VENDOR_ATTR_SURVEY_INFO_NOISE) nla_put_s32(m, RDK_VENDOR_ATTR_SURVEY_INFO_NOISE, -90 - k);
                if (o != RDK_VENDOR_ATTR_SURVEY_INFO_RADAR_NOISE) nla_put_s32(m, RDK_VENDOR_ATTR_SURVEY_INFO_RADAR_NOISE, k & 1);
                if (o != RDK_VENDOR_ATTR_SURVEY_INFO_MAX_RSSI) nla_put_s32(m, RDK_VENDOR_ATTR_SURVEY_INFO_MAX_RSSI, -40 - k);
                if (o != RDK_VENDOR_ATTR_SURVEY_INFO_NON_80211_NOISE) nla_put_s32(m, RDK_VENDOR_ATTR_SURVEY_INFO_NON_80211_NOISE, -95 - k);
                if (o != RDK_VENDOR_ATTR_SURVEY_INFO_CHAN_UTIL) nla_put_u8(m, RDK_VENDOR_ATTR_SURVEY_INFO_CHAN_UTIL, 10 + k);
                if (o != RDK_VENDOR_ATTR_SURVEY_INFO_TIME_ACTIVE) nla_put_u64(m, RDK_VENDOR_ATTR_SURVEY_INFO_TIME_ACTIVE, 1000000ULL + k);
                if (o != RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY) nla_put_u64(m, RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY, 2000ULL + k);
                if (o != RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY_TX) nla_put_u64(m, RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY_TX, 300ULL + k);
                if (o != RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY_RX) nla_put_u64(m, RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY_RX, 400ULL + k);
                if (o != RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY_RX_SELF) nla_put_u64(m, RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY_RX_SELF, 500ULL + k);
                if (o != RDK_VENDOR_ATTR_SURVEY_INFO_TIME_EXT_BUSY) nla_put_u64(m, RDK_VENDOR_ATTR_SURVEY_INFO_TIME_EXT_BUSY, 600ULL + k);
                nla_nest_end(m, en);
            }
            nla_nest_end(m, sv);
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
    hwr_bgk_world.send_calls++;
    r = build_reply(&hwr_bgk_world);
    valid_handler(r, valid_data);
    nlmsg_free(r);
    nlmsg_free(msg);
    return hwr_bgk_world.dump_rc;
}

/* --- hostap-2.10 ieee802_11_common.c:898-1124 (ieee80211_freq_to_channel_ext) and :879-885 (ieee80211_freq_to_chan) --- */
static enum hostapd_hw_mode ieee80211_freq_to_channel_ext(unsigned int freq,
						   int sec_channel,
						   int chanwidth,
						   u8 *op_class, u8 *channel)
{
	u8 vht_opclass;

	/* TODO: more operating classes */

	if (sec_channel > 1 || sec_channel < -1)
		return NUM_HOSTAPD_MODES;

	if (freq >= 2412 && freq <= 2472) {
		if ((freq - 2407) % 5)
			return NUM_HOSTAPD_MODES;

		if (chanwidth)
			return NUM_HOSTAPD_MODES;

		/* 2.407 GHz, channels 1..13 */
		if (sec_channel == 1)
			*op_class = 83;
		else if (sec_channel == -1)
			*op_class = 84;
		else
			*op_class = 81;

		*channel = (freq - 2407) / 5;

		return HOSTAPD_MODE_IEEE80211G;
	}

	if (freq == 2484) {
		if (sec_channel || chanwidth)
			return NUM_HOSTAPD_MODES;

		*op_class = 82; /* channel 14 */
		*channel = 14;

		return HOSTAPD_MODE_IEEE80211B;
	}

	if (freq >= 4900 && freq < 5000) {
		if ((freq - 4000) % 5)
			return NUM_HOSTAPD_MODES;
		*channel = (freq - 4000) / 5;
		*op_class = 0; /* TODO */
		return HOSTAPD_MODE_IEEE80211A;
	}

	switch (chanwidth) {
	case CHANWIDTH_80MHZ:
		vht_opclass = 128;
		break;
	case CHANWIDTH_160MHZ:
		vht_opclass = 129;
		break;
	case CHANWIDTH_80P80MHZ:
		vht_opclass = 130;
		break;
	default:
		vht_opclass = 0;
		break;
	}

	/* 5 GHz, channels 36..48 */
	if (freq >= 5180 && freq <= 5240) {
		if ((freq - 5000) % 5)
			return NUM_HOSTAPD_MODES;

		if (vht_opclass)
			*op_class = vht_opclass;
		else if (sec_channel == 1)
			*op_class = 116;
		else if (sec_channel == -1)
			*op_class = 117;
		else
			*op_class = 115;

		*channel = (freq - 5000) / 5;

		return HOSTAPD_MODE_IEEE80211A;
	}

	/* 5 GHz, channels 52..64 */
	if (freq >= 5260 && freq <= 5320) {
		if ((freq - 5000) % 5)
			return NUM_HOSTAPD_MODES;

		if (vht_opclass)
			*op_class = vht_opclass;
		else if (sec_channel == 1)
			*op_class = 119;
		else if (sec_channel == -1)
			*op_class = 120;
		else
			*op_class = 118;

		*channel = (freq - 5000) / 5;

		return HOSTAPD_MODE_IEEE80211A;
	}

	/* 5 GHz, channels 149..177 */
	if (freq >= 5745 && freq <= 5885) {
		if ((freq - 5000) % 5)
			return NUM_HOSTAPD_MODES;

		if (vht_opclass)
			*op_class = vht_opclass;
		else if (sec_channel == 1)
			*op_class = 126;
		else if (sec_channel == -1)
			*op_class = 127;
		else if (freq <= 5805)
			*op_class = 124;
		else
			*op_class = 125;

		*channel = (freq - 5000) / 5;

		return HOSTAPD_MODE_IEEE80211A;
	}

	/* 5 GHz, channels 100..144 */
	if (freq >= 5500 && freq <= 5720) {
		if ((freq - 5000) % 5)
			return NUM_HOSTAPD_MODES;

		if (vht_opclass)
			*op_class = vht_opclass;
		else if (sec_channel == 1)
			*op_class = 122;
		else if (sec_channel == -1)
			*op_class = 123;
		else
			*op_class = 121;

		*channel = (freq - 5000) / 5;

		return HOSTAPD_MODE_IEEE80211A;
	}

	if (freq >= 5000 && freq < 5900) {
		if ((freq - 5000) % 5)
			return NUM_HOSTAPD_MODES;
		*channel = (freq - 5000) / 5;
		*op_class = 0; /* TODO */
		return HOSTAPD_MODE_IEEE80211A;
	}

	if (freq > 5950 && freq <= 7115) {
		if ((freq - 5950) % 5)
			return NUM_HOSTAPD_MODES;

		switch (chanwidth) {
		case CHANWIDTH_80MHZ:
			*op_class = 133;
			break;
		case CHANWIDTH_160MHZ:
			*op_class = 134;
			break;
		case CHANWIDTH_80P80MHZ:
			*op_class = 135;
			break;
		default:
			if (sec_channel)
				*op_class = 132;
			else
				*op_class = 131;
			break;
		}

		*channel = (freq - 5950) / 5;
		return HOSTAPD_MODE_IEEE80211A;
	}

	if (freq == 5935) {
		*op_class = 136;
		*channel = (freq - 5925) / 5;
		return HOSTAPD_MODE_IEEE80211A;
	}

	/* 56.16 GHz, channel 1..6 */
	if (freq >= 56160 + 2160 * 1 && freq <= 56160 + 2160 * 6) {
		if (sec_channel)
			return NUM_HOSTAPD_MODES;

		switch (chanwidth) {
		case CHANWIDTH_USE_HT:
		case CHANWIDTH_2160MHZ:
			*channel = (freq - 56160) / 2160;
			*op_class = 180;
			break;
		case CHANWIDTH_4320MHZ:
			/* EDMG channels 9 - 13 */
			if (freq > 56160 + 2160 * 5)
				return NUM_HOSTAPD_MODES;

			*channel = (freq - 56160) / 2160 + 8;
			*op_class = 181;
			break;
		case CHANWIDTH_6480MHZ:
			/* EDMG channels 17 - 20 */
			if (freq > 56160 + 2160 * 4)
				return NUM_HOSTAPD_MODES;

			*channel = (freq - 56160) / 2160 + 16;
			*op_class = 182;
			break;
		case CHANWIDTH_8640MHZ:
			/* EDMG channels 25 - 27 */
			if (freq > 56160 + 2160 * 3)
				return NUM_HOSTAPD_MODES;

			*channel = (freq - 56160) / 2160 + 24;
			*op_class = 183;
			break;
		default:
			return NUM_HOSTAPD_MODES;
		}

		return HOSTAPD_MODE_IEEE80211AD;
	}

	return NUM_HOSTAPD_MODES;
}

static enum hostapd_hw_mode ieee80211_freq_to_chan(int freq, u8 *channel)
{
	u8 op_class;

	return ieee80211_freq_to_channel_ext(freq, 0, CHANWIDTH_USE_HT,
					     &op_class, channel);
}

/* --- platform.c:4015-4176 --- */
static int get_channel_stats_handler(struct nl_msg *msg, void *arg)
{
    int i, rem;
    unsigned int freq;
    unsigned char channel;
    struct nlattr *nlattr;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *tb_vendor[RDK_VENDOR_ATTR_MAX + 1];
    struct nlattr *survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_MAX + 1];
    static struct nla_policy vendor_policy[RDK_VENDOR_ATTR_MAX + 1] = {
        [RDK_VENDOR_ATTR_SURVEY_INFO] = { .type = NLA_NESTED },
    };
    static struct nla_policy survey_policy[RDK_VENDOR_ATTR_SURVEY_INFO_MAX + 1] = {
        [RDK_VENDOR_ATTR_SURVEY_INFO_FREQUENCY] = { .type = NLA_U32 },
        [RDK_VENDOR_ATTR_SURVEY_INFO_NOISE] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_SURVEY_INFO_RADAR_NOISE] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_SURVEY_INFO_MAX_RSSI] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_SURVEY_INFO_NON_80211_NOISE] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_SURVEY_INFO_CHAN_UTIL] = { .type = NLA_U8 },
        [RDK_VENDOR_ATTR_SURVEY_INFO_TIME_ACTIVE] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY_TX] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY_RX] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY_RX_SELF] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_SURVEY_INFO_TIME_EXT_BUSY] = { .type = NLA_U64 },
    };
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    channel_stats_arr_t *stats = (channel_stats_arr_t *)arg;

    /* start fix 2 */
    if (stats->arr == NULL || stats->arr_size <= 0) {
        return NL_SKIP;
    }
    /* end fix 2 */

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

    if (tb_vendor[RDK_VENDOR_ATTR_SURVEY_INFO] == NULL) {
        wifi_hal_stats_error_print("%s:%d Survey info attribute is missing\n", __func__, __LINE__);
        return NL_SKIP;
    }

    nla_for_each_nested(nlattr, tb_vendor[RDK_VENDOR_ATTR_SURVEY_INFO], rem) {

        if (nla_parse(survey_info, RDK_VENDOR_ATTR_SURVEY_INFO_MAX, nla_data(nlattr),
            nla_len(nlattr), survey_policy)) {
            wifi_hal_stats_error_print("%s:%d: Failed to parse survey info attibutes\n", __func__,
                __LINE__);
            return NL_SKIP;
        }

        for (i = 0; i <= RDK_VENDOR_ATTR_SURVEY_INFO_MAX; i++) {
            if (survey_policy[i].type != 0 && survey_info[i] == NULL) {
                wifi_hal_stats_error_print("%s:%d Survey info attribute %d is missing\n", __func__,
                    __LINE__, i);
                return NL_SKIP;
            }
        }

        freq = nla_get_u32(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_FREQUENCY]);
        if (ieee80211_freq_to_chan(freq, &channel) == NUM_HOSTAPD_MODES) {
            wifi_hal_stats_error_print("%s:%d Failed to convert frequency %u to channel\n", __func__,
                __LINE__, freq);
            return NL_SKIP;
        }

        for (i = 0; i < stats->arr_size && stats->arr[i].ch_number != channel; i++);
        if (i == stats->arr_size) {
            continue;
        }

        stats->arr[i].ch_noise =
            nla_get_s32(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_NOISE]);
        stats->arr[i].ch_radar_noise =
            nla_get_s32(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_RADAR_NOISE]);
        stats->arr[i].ch_max_80211_rssi =
            nla_get_s32(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_MAX_RSSI]);
        stats->arr[i].ch_non_80211_noise =
            nla_get_s32(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_NON_80211_NOISE]);
        stats->arr[i].ch_utilization =
            nla_get_u8(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_CHAN_UTIL]);
        stats->arr[i].ch_utilization_total =
            nla_get_u64(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_TIME_ACTIVE]);
        stats->arr[i].ch_utilization_busy =
            nla_get_u64(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY]);
        stats->arr[i].ch_utilization_busy_tx =
            nla_get_u64(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY_TX]);
        stats->arr[i].ch_utilization_busy_rx =
            nla_get_u64(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY_RX]);
        stats->arr[i].ch_utilization_busy_self =
            nla_get_u64(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY_RX_SELF]);
        stats->arr[i].ch_utilization_busy_ext =
            nla_get_u64(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_TIME_EXT_BUSY]);
    }

    return NL_SKIP;
}

static int get_channel_stats(wifi_interface_info_t *interface,
    wifi_channelStats_t *channel_stats_arr, int channel_stats_arr_size)
{
    struct nl_msg *msg;
    int ret = RETURN_ERR;
    channel_stats_arr_t stats = { .arr = channel_stats_arr, .arr_size = channel_stats_arr_size };

    msg = nl80211_drv_vendor_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, OUI_COMCAST,
        RDK_VENDOR_NL80211_SUBCMD_GET_SURVEY);
    if (msg == NULL) {
        wifi_hal_stats_error_print("%s:%d Failed to create NL command\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    ret = nl80211_send_and_recv(msg, get_channel_stats_handler, &stats, NULL, NULL);
    if (ret) {
        wifi_hal_stats_error_print("%s:%d Failed to send NL message\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

INT wifi_getRadioChannelStats(INT radioIndex, wifi_channelStats_t *input_output_channelStats_array,
    INT array_size)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;

    wifi_hal_stats_dbg_print("%s:%d: Get radio stats for index: %d\n", __func__, __LINE__,
        radioIndex);

    /* start fix 1 */
    if (input_output_channelStats_array == NULL && array_size != 0) {
        wifi_hal_stats_error_print("%s:%d: NULL channel stats array (size %d)\n", __func__, __LINE__,
            array_size);
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
    if (get_channel_stats(interface, input_output_channelStats_array, array_size)) {
        wifi_hal_stats_error_print("%s:%d: Failed to get channel stats for radio index: %d\n", __func__,
            __LINE__, radioIndex);
        return RETURN_ERR;
    }

    return RETURN_OK;
}
