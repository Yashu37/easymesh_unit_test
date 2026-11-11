/*
 * HANDLER: wifi_hal_setRMBeaconRequest (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:3905-4088 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It checks peer_mac / in_req / out_DialogToken, finds the AP
 * interface, validates channel / op class, mode and the wide-band channel, translates the optional fields of the wifi_BeaconRequest_t (SSID copy, reporting condition, detail, the zero-terminated channel
 * report, requested element IDs, wide-band channel) into the optional arguments of wifi_rrm_send_beacon_req and stores the returned dialog token in *out_DialogToken.
 *
 * Scaffolding only: get_interface_by_vap_index / ieee80211_chan_to_freq / wifi_rrm_send_beacon_req are recording stubs over the runner's world; wifi_strncpy and wifi_strnlen are the real functions
 * (wifi_hal_nl80211_utils.c:5019, wifi_hal_priv.h:1484); the *_print macros go to the log sink hwr_print.  Renamed hwr_sg_wifi_hal_setRMBeaconRequest.
 */
#include "hwr_wrb.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VHT_OPER_CHANWIDTH_80P80MHZ 3
#define wifi_hal_dbg_print(format, ...)          hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)        hwr_print(1, format, ##__VA_ARGS__)
#define g_wifi_hal hwr_wrb_world.hal
#define get_interface_by_vap_index hwr_wrb_get_interface_by_vap_index
#define ieee80211_chan_to_freq hwr_wrb_ieee80211_chan_to_freq
#define wifi_rrm_send_beacon_req hwr_wrb_wifi_rrm_send_beacon_req
#define wifi_strncpy hwr_wrb_wifi_strncpy
#define wifi_hal_setRMBeaconRequest hwr_sg_wifi_hal_setRMBeaconRequest
/* src/wifi_hal.c:2628-2634 */
#define _IS_INVALID_ARG(expr) ({ \
    bool __not_valid = (expr); \
    if (__not_valid) { \
        wifi_hal_error_print("%s:%d: Invalid argument; " #expr "\n", __func__, __LINE__); \
    } \
    __not_valid; \
})

hwr_wrb_world_t hwr_wrb_world;
/* src/wifi_hal_priv.h:1484 */
static inline size_t wifi_strnlen(const char *src, size_t maxlen) { return src ? strnlen(src, maxlen) : 0; }

extern "C" {
wifi_interface_info_t *get_interface_by_vap_index(unsigned int vap_index)
{
    return vap_index < HWR_WRB_MAXI ? &hwr_wrb_world.ifs[vap_index] : NULL;
}
/* table stand-in: usable op class 1..254 except 99, channel 1..233 */
int ieee80211_chan_to_freq(const char *country, u8 op_class, u8 chan)
{
    hwr_wrb_world.freq_calls++;
    if (country == NULL) hwr_wrb_world.freq_null_country++;
    if (op_class == 0 || op_class == 99 || chan == 0 || chan > 233) return -1;
    return 5000 + 5 * chan;
}
/* wifi_hal_nl80211_utils.c:5019-5041 */
int wifi_strncpy(char *dest, size_t dest_size, const char *src, size_t count)
{
    size_t srclen;

    if (dest == NULL || src == NULL || dest_size == 0)
        return -1;

    dest[0] = '\0';
    if (count >= dest_size)
        return -1;

    srclen = strnlen(src, dest_size);
    count = (srclen < count) ? srclen : count;

    // Check for overlap
    if ((src >= dest && src < dest + dest_size) ||
        (dest >= src && dest < src + count))
        return -1;

    memcpy(dest, src, count);
    dest[count] = '\0';
    return 0;
}
int wifi_rrm_send_beacon_req(struct wifi_interface_info_t *interface, const u8 *addr, u16 num_of_repetitions, u8 measurement_request_mode, u8 oper_class, u8 channel, u16 random_interval,
    u16 measurement_duration, u8 mode, const u8 *bssid, struct wpa_ssid_value *ssid, u8 *rep_cond, u8 *rep_cond_threshold, u8 *rep_detail, const u8 *ap_ch_rep, unsigned int ap_ch_rep_len,
    const u8 *req_elem, unsigned int req_elem_len, u8 *ch_width, u8 *ch_center_freq0, u8 *ch_center_freq1, u8 last_indication)
{
    hwr_wrb_world_t *w = &hwr_wrb_world;
    w->send_calls++; w->send_iface = interface; w->send_addr = addr; w->send_nrep = num_of_repetitions; w->send_req_mode = measurement_request_mode; w->send_oc = oper_class; w->send_ch = channel;
    w->send_rand = random_interval; w->send_dur = measurement_duration; w->send_mode = mode; memcpy(w->send_bssid, bssid, 6); w->send_last = last_indication;
    w->ssid_null = ssid == NULL; if (ssid) { w->ssid_len = ssid->ssid_len; memcpy(w->ssid_val, ssid->ssid, 32); w->ssid_val[32] = 0; }
    w->cond_null = rep_cond == NULL; if (rep_cond) w->cond = *rep_cond;
    w->thr_null = rep_cond_threshold == NULL; if (rep_cond_threshold) w->thr = *rep_cond_threshold;
    w->det_null = rep_detail == NULL; if (rep_detail) w->det = *rep_detail;
    w->chrep_null = ap_ch_rep == NULL; w->chrep_len = ap_ch_rep_len; w->chrep_ptr = ap_ch_rep;
    if (ap_ch_rep && ap_ch_rep_len <= 64) memcpy(w->chrep, ap_ch_rep, ap_ch_rep_len);
    w->elem_null = req_elem == NULL; w->elem_len = req_elem_len; w->elem_ptr = req_elem;
    w->w_null = ch_width == NULL; if (ch_width) w->w = *ch_width;
    w->c0_null = ch_center_freq0 == NULL; if (ch_center_freq0) w->c0 = *ch_center_freq0;
    w->c1_null = ch_center_freq1 == NULL; if (ch_center_freq1) w->c1 = *ch_center_freq1;
    w->mutex_held_at_send = pthread_mutex_trylock(&hwr_wrb_world.hal.hapd_lock) != 0;
    return w->send_ret;
}

/* --- wifi_hal.c:3905-4088 --- */
INT wifi_hal_setRMBeaconRequest(UINT apIndex,
                            mac_address_t peer_mac,
                            wifi_BeaconRequest_t *in_req,
                            UCHAR *out_DialogToken)
{
    wifi_interface_info_t *interface;
    struct wpa_ssid_value ssid = {0}, *ssid_p = NULL;
    u8 measurement_request_mode = 0, last_indication = 0;

    u8 rep_cond, rep_cond_threshold;
    u8* rep_cond_p = NULL, *rep_cond_threshold_p = NULL;
    u8 rep_detail;
    u8* rep_detail_p = NULL;
    u8* ap_ch_rep_p = NULL;
    unsigned int ap_ch_rep_len = 0;
    u8* req_elem_p = NULL;
    unsigned int req_elem_len = 0;
    u8 channel_width, channel_center_ch0, channel_center_ch1;
    u8 *channel_width_p = NULL, *channel_center_ch0_p = NULL, *channel_center_ch1_p = NULL;
    int ret_dialog_token;

    // - verify input params
    if (_IS_INVALID_ARG(peer_mac == NULL)) {
        return WIFI_HAL_INVALID_ARGUMENTS;
    }

    if (_IS_INVALID_ARG(in_req == NULL)) {
        return WIFI_HAL_INVALID_ARGUMENTS;
    }

    if (_IS_INVALID_ARG(out_DialogToken == NULL)) {
        return WIFI_HAL_INVALID_ARGUMENTS;
    }

    interface = get_interface_by_vap_index(apIndex);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: [BTM] REQ_BEACON - interface for ap index:%u not found\n", __func__, __LINE__, apIndex);
        return WIFI_HAL_ERROR;
    }

    if (interface->vap_info.vap_mode != wifi_vap_mode_ap) {
        wifi_hal_error_print("%s:%d: [BTM] REQ_BEACON - interface with ap index:%u not in AP mode\n", __func__, __LINE__, apIndex);
        return WIFI_HAL_ERROR;
    }

    // (1) peer_mac -> addr
    // (2) in_req->numRepetitions -> num_of_repetitions

    // (3)
    measurement_request_mode = 0;

    // (4) in_req->opClass -> op_class;
    // (5) in_req->channel -> channel;
    /* Quote from 80211-2016, Chapter 9.4.2.21.7 Beacon request:
    "For operating classes that encompass a primary channel but do not identify the location of the primary
    channel, the Channel Number field value is either 0 or 255; otherwise, the Channel Number field value is 0,
    255, or the channel number for which the measurement request applies and is defined within an operating
    class as shown in Annex E." */
    if (in_req->channel != 0 && in_req->channel != 255) {
        if (ieee80211_chan_to_freq(NULL, in_req->opClass, in_req->channel) < 0) {
            wifi_hal_error_print("%s:%d: [BTM] REQ_BEACON - channel/op_class combination invalid\n", __func__, __LINE__);
            return WIFI_HAL_ERROR;
        }
    }

    // (6) in_req->randomizationInterval -> random_interval
    // (7) in_req->duration -> measurement_duration
    // (8) in_req->mode -> mode
    if (in_req->mode > 2) {
        wifi_hal_error_print("%s:%d: [BTM] REQ_BEACON - mode is invalid\n", __func__, __LINE__);
        return WIFI_HAL_ERROR;
    }

    // (9) in_req->bssid -> bssid

    // (10)
    if (in_req->ssidPresent) {
        wifi_strncpy(ssid.ssid, sizeof(ssid.ssid), in_req->ssid, sizeof(in_req->ssid)-1);
        ssid.ssid_len = wifi_strnlen(ssid.ssid, sizeof(ssid.ssid)-1);
        ssid_p = &ssid;
    }

    // (11)
    if (in_req->beaconReportingPresent) {
        rep_cond = in_req->beaconReporting.condition;
        rep_cond_threshold = in_req->beaconReporting.threshold;
        rep_cond_p = &rep_cond;
        rep_cond_threshold_p = &rep_cond_threshold;
    }

    // (12)
    if (in_req->reportingRetailPresent) {
        rep_detail = in_req->reportingDetail;
        rep_detail_p = &rep_detail;
    }

    // (13)
    if (in_req->channelReportPresent) {
        /* Count valid channels from the zero-terminated channelReport.channels array and pass the correct length to wifi_rrm_send_beacon_req() */
        ap_ch_rep_len = 0;
        while (ap_ch_rep_len < MAX_CHANNELS_REPORT &&
               in_req->channelReport.channels[ap_ch_rep_len] != 0) {
            ap_ch_rep_len++;
        }
        if (ap_ch_rep_len > 0) {
            ap_ch_rep_p = in_req->channelReport.channels;
        } else if (in_req->channel == 255) {
            wifi_hal_error_print("%s:%d: [BTM] REQ_BEACON - channel report is empty for channel 255\n", __func__, __LINE__);
            return WIFI_HAL_ERROR;
        }
    }

    // (14)
    if (in_req->requestedElementIDSPresent) {
        req_elem_len = MAX_REQUESTED_ELEMS;
        req_elem_p = in_req->requestedElementIDS.ids;
    }

    // (15)
    if (in_req->wideBandWidthChannelPresent) {
        channel_width = in_req->wideBandwidthChannel.bandwidth;
        channel_center_ch0 = in_req->wideBandwidthChannel.centerSeg0;
        channel_center_ch1 = in_req->wideBandwidthChannel.centerSeg1;

        if (/*channel_width < VHT_OPER_CHANWIDTH_20_40MHZ ||*/
            channel_width > VHT_OPER_CHANWIDTH_80P80MHZ) {
            wifi_hal_error_print("%s:%d: [BTM] REQ_BEACON - channel width is invalid\n", __func__, __LINE__);
            return WIFI_HAL_ERROR;
        }

        /* According to IEE80211-2016, Chapter 21.3.14 Channelization */
        if (ieee80211_chan_to_freq(NULL, in_req->opClass, channel_center_ch0) < 0) {
            wifi_hal_error_print("%s:%d: [BTM] REQ_BEACON - channel center frequency 0 is invalid\n", __func__, __LINE__);
        } else {
            channel_center_ch0_p = &channel_center_ch0;
        }

        if (ieee80211_chan_to_freq(NULL, in_req->opClass, channel_center_ch1) < 0) {
            wifi_hal_error_print("%s:%d: [BTM] REQ_BEACON - channel center frequency 1 is invalid\n", __func__, __LINE__);
        } else {
            channel_center_ch1_p = &channel_center_ch1;
        }

        channel_width_p = &channel_width;
    }

    // (16)
    if (in_req->extdRequestedElementIDSPresent) {
        // - extdRequestedElementIDS: not used by hostapd sources
    }

    // (17)
    if (in_req->vendorSpecificPresent) {
        // - vendorSpecific: not used by hostapd sources
    }

    // (18)
    // last_indication: used by hostapd function, but not specified by API
    last_indication = 0;

    wifi_hal_dbg_print("%s:%d: [BTM] Send beacon request...\n", __func__, __LINE__);
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    // - interface->u.ap.hapd has to be locked by mutex g_wifi_hal.hapd_lock
    ret_dialog_token = wifi_rrm_send_beacon_req(interface, peer_mac, in_req->numRepetitions,
            measurement_request_mode, in_req->opClass, in_req->channel, in_req->randomizationInterval,
            in_req->duration, in_req->mode, in_req->bssid,
            ssid_p, rep_cond_p, rep_cond_threshold_p, rep_detail_p,
            ap_ch_rep_p, ap_ch_rep_len,
            req_elem_p, req_elem_len,
            channel_width_p, channel_center_ch0_p, channel_center_ch1_p,
            last_indication);
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

    if (ret_dialog_token < 0) {
        wifi_hal_error_print("%s:%d: [BTM] Send beacon request failed!\n", __func__, __LINE__);
        return WIFI_HAL_ERROR;
    }

    *out_DialogToken = ret_dialog_token;
    /* g_DialogToken bit is set inside wifi_rrm_send_beacon_req() against the VAP
     * that actually transmitted the request (may differ from apIndex for MLO). */

    return WIFI_HAL_SUCCESS;
}
}
