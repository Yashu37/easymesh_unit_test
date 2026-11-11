/*
 * HANDLER: wifi_hal_setNeighborReports (src/wifi_hal.c)
 *
 * Function copied from rdk-wifi-hal (verbatim apart from fix 1): src/wifi_hal.c:4170-4416 (~/Desktop/G/rdk-wifi-hal), HOSTAPD_VERSION >= 210 branch.  This file holds the ORIGINAL code with fix 1 applied (start fix 1 / end fix 1 markers; the unfixed copy is the reproducer).  It checks the arguments, finds the
 * AP interface, takes g_wifi_hal.hapd_lock, logs hapd->conf->iface, clears the neighbour database, requires the neighbour report bit in hapd->conf->radio_measurements[0] and, for every report, builds a
 * neighbour report element in a wpabuf (13 fixed bytes plus every optional sub-element that is flagged present, buffer sized 13 + 5 + sub_max_size) and installs it with hostapd_neighbor_set().
 *
 * Scaffolding only: get_interface_by_vap_index / hostapd_free_neighbor_db / hostapd_neighbor_set are recording stubs over the runner's world; wpabuf_alloc / wpabuf_put_* / wpabuf_free are the hostapd wpabuf
 * API over an exact-size heap block (no bounds check, like the real one); wifi_strncpy is the real function (wifi_hal_nl80211_utils.c:5019) and wifi_strnlen the real inline (wifi_hal_priv.h:1484); the WNM_NEIGHBOR_*
 * constants are the hostapd values; the *_print macros go to the log sink hwr_print.  Renamed hwr_sg_wifi_hal_setNeighborReports.
 */
#include "hwr_wnr.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HOSTAPD_VERSION 210
#define WNM_NEIGHBOR_TSF                         1
#define WNM_NEIGHBOR_CONDENSED_COUNTRY_STRING    2
#define WNM_NEIGHBOR_BSS_TRANSITION_CANDIDATE    3
#define WNM_NEIGHBOR_BSS_TERMINATION_DURATION    4
#define WNM_NEIGHBOR_BEARING                     5
#define WNM_NEIGHBOR_WIDE_BW_CHAN                6
#define WNM_NEIGHBOR_HT_CAPAB                   45
#define WNM_NEIGHBOR_HT_OPER                    61
#define WNM_NEIGHBOR_SEC_CHAN_OFFSET            62
#define WNM_NEIGHBOR_MEASUREMENT_PILOT          66
#define WNM_NEIGHBOR_RRM_ENABLED_CAPABILITIES   70
#define WNM_NEIGHBOR_VHT_CAPAB                 191
#define WNM_NEIGHBOR_VHT_OPER                  192
#define wifi_hal_dbg_print(format, ...)          hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)        hwr_print(1, format, ##__VA_ARGS__)
#define g_wifi_hal hwr_wnr_world.hal
#define get_interface_by_vap_index hwr_wnr_get_interface_by_vap_index
#define hostapd_free_neighbor_db hwr_wnr_hostapd_free_neighbor_db
#define hostapd_neighbor_set hwr_wnr_hostapd_neighbor_set
#define wpabuf_alloc hwr_wnr_wpabuf_alloc
#define wpabuf_free hwr_wnr_wpabuf_free
#define wpabuf_put_data hwr_wnr_wpabuf_put_data
#define wpabuf_put_u8 hwr_wnr_wpabuf_put_u8
#define wpabuf_put_le16 hwr_wnr_wpabuf_put_le16
#define wpabuf_put_le32 hwr_wnr_wpabuf_put_le32
#define wpabuf_put_le64 hwr_wnr_wpabuf_put_le64
#define wifi_strncpy hwr_wnr_wifi_strncpy
#define wifi_hal_setNeighborReports hwr_sg_wifi_hal_setNeighborReports
/* src/wifi_hal.c:2628-2634 */
#define _IS_INVALID_ARG(expr) ({ \
    bool __not_valid = (expr); \
    if (__not_valid) { \
        wifi_hal_error_print("%s:%d: Invalid argument; " #expr "\n", __func__, __LINE__); \
    } \
    __not_valid; \
})

hwr_wnr_world_t hwr_wnr_world;
/* src/wifi_hal_priv.h:1484 */
static inline size_t wifi_strnlen(const char *src, size_t maxlen) { return src ? strnlen(src, maxlen) : 0; }

extern "C" {
wifi_interface_info_t *get_interface_by_vap_index(unsigned int vap_index)
{
    return vap_index < HWR_WNR_MAXI ? &hwr_wnr_world.ifs[vap_index] : NULL;
}
void hostapd_free_neighbor_db(struct hostapd_data *hapd) { hwr_wnr_world.free_calls++; }
int hostapd_neighbor_set(struct hostapd_data *hapd, const u8 *bssid, const struct wpa_ssid_value *ssid, const struct wpabuf *nr, const struct wpabuf *lci, const struct wpabuf *civic, int stationary, u8 bss_parameters)
{
    hwr_wnr_world_t *w = &hwr_wnr_world;
    int k = w->set_calls++;
    w->mutex_held_at_set = pthread_mutex_trylock(&w->hal.hapd_lock) != 0;
    if (k < HWR_WNR_MAXSET) {
        memcpy(w->set_bssid[k], bssid, 6); w->set_ssid_len[k] = ssid->ssid_len; memcpy(w->set_ssid[k], ssid->ssid, 32); w->set_ssid[k][32] = 0;
        w->set_nr_len[k] = nr->used; memcpy(w->set_nr[k], nr->buf, nr->used < HWR_WNR_NRCAP ? nr->used : HWR_WNR_NRCAP);
    }
    return (w->set_fail_at && w->set_calls == w->set_fail_at) ? -1 : 0;
}
/* hostapd wpabuf API over an exact-size heap block (no bounds check) */
struct wpabuf *wpabuf_alloc(size_t len)
{
    hwr_wnr_world_t *w = &hwr_wnr_world;
    w->alloc_calls++;
    if (w->alloc_fail_at && w->alloc_calls == w->alloc_fail_at) return NULL;
    struct wpabuf *b = (struct wpabuf *)calloc(1, sizeof(*b));
    b->size = len; b->buf = (u8 *)calloc(1, len);
    w->live_bufs++;
    return b;
}
void wpabuf_free(struct wpabuf *b) { if (b) { hwr_wnr_world.live_bufs--; free(b->buf); free(b); } }
void *wpabuf_put_data(struct wpabuf *b, const void *data, size_t len) { u8 *p = b->buf + b->used; b->used += len; memcpy(p, data, len); return p; }
void wpabuf_put_u8(struct wpabuf *b, u8 v) { b->buf[b->used++] = v; }
void wpabuf_put_le16(struct wpabuf *b, u16 v) { b->buf[b->used] = (u8)v; b->buf[b->used + 1] = (u8)(v >> 8); b->used += 2; }
void wpabuf_put_le32(struct wpabuf *b, u32 v) { for (int k = 0; k < 4; k++) b->buf[b->used + k] = (u8)(v >> (8 * k)); b->used += 4; }
void wpabuf_put_le64(struct wpabuf *b, u64 v) { for (int k = 0; k < 8; k++) b->buf[b->used + k] = (u8)(v >> (8 * k)); b->used += 8; }
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

/* --- wifi_hal.c:4170-4416 --- */
INT wifi_hal_setNeighborReports(UINT apIndex, UINT numNeighborReports, wifi_NeighborReport_t *neighborReports)
{
    wifi_interface_info_t *interface;
    struct hostapd_data *hapd;
    struct wpa_ssid_value ssid;
    uint i;
    int ret = RETURN_ERR;

    // - verify input params
    if (_IS_INVALID_ARG(neighborReports == NULL)) {
        return WIFI_HAL_INVALID_ARGUMENTS;
    }

    if (_IS_INVALID_ARG(numNeighborReports < 1)) {
        return WIFI_HAL_INVALID_ARGUMENTS;
    }

    interface = get_interface_by_vap_index(apIndex);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: [BTM] interface for ap index:%u not found\n", __func__, __LINE__, apIndex);
        return WIFI_HAL_ERROR;
    }

    if (interface->vap_info.vap_mode != wifi_vap_mode_ap) {
        wifi_hal_error_print("%s:%d: [BTM] interface with ap index:%u not in AP mode\n", __func__, __LINE__, apIndex);
        return WIFI_HAL_ERROR;
    }

    /* ---------- start fix 1: hapd->conf is NULL while hostapd is not set up for the VAP; it was dereferenced for the log line below (and for radio_measurements) while holding hapd_lock. */
    if (interface->u.ap.hapd.conf == NULL) {
        wifi_hal_error_print("%s:%d: [BTM] hostapd configuration of ap index:%u is not available\n", __func__, __LINE__, apIndex);
        return WIFI_HAL_ERROR;
    }
    /* ---------- end fix 1 */

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    hapd = &interface->u.ap.hapd;
    wifi_hal_dbg_print("%s:%d: [BTM] HAPD Interface name:%s\n", __func__, __LINE__, hapd->conf->iface);

    // - Clear the existing neighbor report database
    hostapd_free_neighbor_db(hapd);

    if (!(hapd->conf->radio_measurements[0] & WLAN_RRM_CAPS_NEIGHBOR_REPORT)) {
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
        wifi_hal_error_print("%s:%d: [BTM] Neighbor report is not enabled\n", __func__, __LINE__);
        return WIFI_HAL_ERROR;
    }

    for (i = 0; i < numNeighborReports; ++i)
    {
        struct wpabuf *nr = NULL;
        size_t sub_max_size;
        wifi_NeighborReport_t* rep = &neighborReports[i];
        // - 1: BBSID -> neighborReports[i].bssid

        // - 2: SSID -> neighborReports[i].target_ssid,
        wifi_strncpy(ssid.ssid, sizeof(ssid.ssid), rep->target_ssid, SSID_MAX_LEN-1);
        ssid.ssid_len = wifi_strnlen(ssid.ssid, SSID_MAX_LEN-1);

        // - 3: nr ->
        // * Neighbor Report element size nr = BSSID + BSSID info + op_class + chan + phy type + ...
        // * ... + wide bandwidth channel subelement.
        // BSSID    - 6 bytes -> bssid_t
        // info     - 4 bytes -> uint32_t
        // opClass  - 1 byte
        // channel  - 1 byte
        // phyTable - 1 byte ==> 13 bytes
        //
        // (OPTIONAL SUBELEMENTS):
        // - TSF Information:                      6 bytes
        // - Condensed Country String:             4 bytes
        // - wide bandwidth channel subelement:    5 bytes
        // - BSS Transition Candidate Preference:  3 bytes
        // - BSS Termination Duration:            12 bytes
        // - Bearing:                             10 bytes
        // - HT Capabilities subelement:          28 bytes
        // - VHT Capabilities subelement:         14 bytes
        // - HT Operations subelement:            24 bytes
        // - VHT Operations subelement:            7 bytes
        // - Secondary Channel Offset subelement:  3 bytes
        // - RM Enabled Capabilities:              7 bytes
        // - Measurement Pilot Transmission:       2 + (1 + (2 + (5 + MAX_VENDOR_SPECIFIC(32)))) bytes
        // - Vendor Specific:                      2 + (5 + MAX_VENDOR_SPECIFIC(32)) bytes
        sub_max_size = 6 + 4 + 5 + 3 + 12 + 10 + 28 + 14 + 24 + 7 + 3 + 7
               + 2 + (1 + (2 + (5 + MAX_VENDOR_SPECIFIC)))
               + 2 + (5 + MAX_VENDOR_SPECIFIC)
               + 10; // extra bytes for safety;

        nr = wpabuf_alloc(sizeof(bssid_t) + sizeof(uint32_t) + 1 + 1 + 1 + 5 + sub_max_size);
        if (!nr) {
            wifi_hal_error_print("%s:%d: [BTM] Cannot allocate wpa buffer\n", __func__, __LINE__);
            goto failure;
        }

        wpabuf_put_data(nr, rep->bssid, sizeof(bssid_t));
        wpabuf_put_le32(nr, rep->info);
        wpabuf_put_u8(nr, rep->opClass);
        wpabuf_put_u8(nr, rep->channel);
        wpabuf_put_u8(nr, rep->phyTable);

        /*
        * Wide Bandwidth Channel subelement may be needed to allow the
        * receiving STA to send packets to the AP. See IEEE P802.11-REVmc/D5.0
        * Figure 9-301.
        */
        // - wide bandwidth channel: 5 bytes
        if (rep->wideBandWidthChannelPresent) {
            wpabuf_put_u8(nr, WNM_NEIGHBOR_WIDE_BW_CHAN);
            wpabuf_put_u8(nr, 3);
            wpabuf_put_u8(nr, rep->wideBandwidthChannel.bandwidth);
            wpabuf_put_u8(nr, rep->wideBandwidthChannel.centerSeg0);
            wpabuf_put_u8(nr, rep->wideBandwidthChannel.centerSeg1);
        }

        // - TSF Information: 6 bytes
        if (rep->tsfPresent) {
            wpabuf_put_u8(nr, WNM_NEIGHBOR_TSF);
            wpabuf_put_u8(nr, 4);
            wpabuf_put_le16(nr, rep->tsfInfo.offset);
            wpabuf_put_le16(nr, rep->tsfInfo.interval);
        }

        // - Condensed Country String: 4 bytes
        if (rep->condensedCountrySringPresent) {
            wpabuf_put_u8(nr, WNM_NEIGHBOR_CONDENSED_COUNTRY_STRING);
            wpabuf_put_u8(nr, 2);
            wpabuf_put_u8(nr, rep->condensedCountryStr.condensedStr[0]);
            wpabuf_put_u8(nr, rep->condensedCountryStr.condensedStr[1]);
        }

        // - BSS Transition Candidate Preference: 3 bytes
        if (rep->bssTransitionCandidatePreferencePresent) {
            wpabuf_put_u8(nr, WNM_NEIGHBOR_BSS_TRANSITION_CANDIDATE);
            wpabuf_put_u8(nr, 1);
            wpabuf_put_u8(nr, rep->bssTransitionCandidatePreference.preference);
        }

        // - BSS Termination Duration: 12 bytes
        if (rep->btmTerminationDurationPresent) {
            wpabuf_put_u8(nr, WNM_NEIGHBOR_BSS_TERMINATION_DURATION);
            wpabuf_put_u8(nr, 10);
            wpabuf_put_le64(nr, rep->btmTerminationDuration.tsf);
            wpabuf_put_le16(nr, rep->btmTerminationDuration.duration);
        }

        // - Bearing: 10 bytes
        if (rep->bearingPresent) {
            wpabuf_put_u8(nr, WNM_NEIGHBOR_BEARING);
            wpabuf_put_u8(nr, 8);
            wpabuf_put_le16(nr, rep->bearing.bearing);
            wpabuf_put_le32(nr, rep->bearing.dist);
            wpabuf_put_le16(nr, rep->bearing.height);
        }

        // - HT Capabilities subelement: 2+(2+1+16+2+4+1) => 2+26 => 28 bytes
        if (rep->htCapsPresent) {
            wpabuf_put_u8(nr, WNM_NEIGHBOR_HT_CAPAB);
            wpabuf_put_u8(nr, 26);
            wpabuf_put_le16(nr, rep->htCaps.info);
            wpabuf_put_u8(nr, rep->htCaps.ampduParams);
            wpabuf_put_data(nr, rep->htCaps.mcs, sizeof(rep->htCaps.mcs));
            wpabuf_put_le16(nr, rep->htCaps.extended);
            wpabuf_put_le32(nr, rep->htCaps.txBeamCaps);
            wpabuf_put_u8(nr, rep->htCaps.aselCaps);
        }

        // - HT Operations subelement: 24 bytes
        if (rep->htOpPresent) {
            wpabuf_put_u8(nr, WNM_NEIGHBOR_HT_OPER);
            wpabuf_put_u8(nr, 22);
            wpabuf_put_u8(nr, rep->htOp.primary);
            wpabuf_put_data(nr, rep->htOp.opInfo, sizeof(rep->htOp.opInfo));
            wpabuf_put_data(nr, rep->htOp.mcs, sizeof(rep->htOp.mcs));
        }

        // - VHT Capabilities subelement: 14 bytes
        if (rep->vhtCapsPresent) {
            wpabuf_put_u8(nr, WNM_NEIGHBOR_VHT_CAPAB);
            wpabuf_put_u8(nr, 12);
            wpabuf_put_le32(nr, rep->vbhtCaps.info);
            // The Supported VHT-MCS and NSS Set field is 64 bits long, but is broken
            // into 4 16 bit fields for convenience.
            wpabuf_put_le16(nr, rep->vbhtCaps.mcs);
            wpabuf_put_le16(nr, rep->vbhtCaps.rxHighestSupportedRate);
            wpabuf_put_le16(nr, rep->vbhtCaps.txVHTmcs);
            wpabuf_put_le16(nr, rep->vbhtCaps.txHighestSupportedRate);
        }

        // - VHT Operations subelement: 7 bytes
        if (rep->vhtOpPresent) {
            wpabuf_put_u8(nr, WNM_NEIGHBOR_VHT_OPER);
            wpabuf_put_u8(nr, 5);
            wpabuf_put_u8(nr, rep->vhtOp.opInfo.bandwidth);
            wpabuf_put_u8(nr, rep->vhtOp.opInfo.centerSeg0);
            wpabuf_put_u8(nr, rep->vhtOp.opInfo.centerSeg1);
            wpabuf_put_le16(nr, rep->vhtOp.mcs_nss);
        }

        // - Secondary Channel Offset subelement: 3 bytes
        if (rep->secondaryChannelOffsetPresent) {
            wpabuf_put_u8(nr, WNM_NEIGHBOR_SEC_CHAN_OFFSET);
            wpabuf_put_u8(nr, 1);
            wpabuf_put_u8(nr, rep->secondaryChannelOffset.secondaryChOffset);
        }

        // - RM Enabled Capabilities: 7 bytes
        if (rep->rmEnabledCapsPresent) {
            wpabuf_put_u8(nr, WNM_NEIGHBOR_RRM_ENABLED_CAPABILITIES);
            wpabuf_put_u8(nr, 5);
            wpabuf_put_data(nr, rep->rmEnabledCaps.capabilities, sizeof(rep->rmEnabledCaps.capabilities));
        }

#define WNM_NEIGHBOR_VENDOR_SPEC 221
        // - See 9.4.2.26
        // - Vendor Specific: 2 + (5 + MAX_VENDOR_SPECIFIC(32)) bytes
        if (rep->vendorSpecificPresent) {
            wpabuf_put_u8(nr, WNM_NEIGHBOR_VENDOR_SPEC);
            wpabuf_put_u8(nr, 5 + MAX_VENDOR_SPECIFIC);
            wpabuf_put_data(nr, rep->vendorSpecific.oui, sizeof(rep->vendorSpecific.oui));
            wpabuf_put_data(nr, rep->vendorSpecific.buff, sizeof(rep->vendorSpecific.buff));
        }

        // See 9.4.2.42, 9.4.3, 9.4.2.26
        // - Measurement Pilot Transmission:  2 + (1 + (2 + (5 + MAX_VENDOR_SPECIFIC(32)))) bytes
        if (rep->msmtPilotTransmissionPresent) {
            wpabuf_put_u8(nr, WNM_NEIGHBOR_MEASUREMENT_PILOT);
            wpabuf_put_u8(nr, rep->msmtPilotTransmission.pilot);
            // --- Vendor Specific subelement:
            wpabuf_put_u8(nr, WNM_NEIGHBOR_VENDOR_SPEC);
            wpabuf_put_u8(nr, 5 + MAX_VENDOR_SPECIFIC);
            wpabuf_put_data(nr, rep->msmtPilotTransmission.vendorSpecific.oui,
                sizeof(rep->msmtPilotTransmission.vendorSpecific.oui));
            wpabuf_put_data(nr, rep->msmtPilotTransmission.vendorSpecific.buff,
                sizeof(rep->msmtPilotTransmission.vendorSpecific.buff));
        }

#if HOSTAPD_VERSION >= 210 //2.10
        ret = hostapd_neighbor_set(hapd, rep->bssid, &ssid, nr, NULL, NULL, 0, 0);
#else
        ret = hostapd_neighbor_set(hapd, rep->bssid, &ssid, nr, NULL, NULL, 0);
#endif
        wpabuf_free(nr);
        if (ret)
            goto failure;
    }

    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    return WIFI_HAL_SUCCESS;

failure:
    hostapd_free_neighbor_db(hapd);
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    return WIFI_HAL_ERROR;
}
}
