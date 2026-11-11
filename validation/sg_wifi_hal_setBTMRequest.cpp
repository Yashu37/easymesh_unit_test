/*
 * HANDLER: wifi_hal_setBTMRequest (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:3718-3898 (~/Desktop/G/rdk-wifi-hal) together with the static helper build_candidates_list and its constants (NEI_LEN, NEIREP_LEN, MAX_TOKENS).
 * This file holds the ORIGINAL code (no fixes).  It reads request->requestMode, checks peerMac / request, finds the AP interface, looks the station up under g_wifi_hal.hapd_lock, builds the BSS termination
 * sub-element, the candidate list (build_candidates_list into a malloc'ed NEIREP_LEN buffer) and the URL copy (malloc(request->urlLen + 1) + wifi_strncpy) and sends the BSS Transition Management Request.
 *
 * Scaffolding only: get_interface_by_vap_index / ap_get_sta / wifi_wnm_send_bss_tm_req are recording stubs over the runner's world; wifi_strncpy is the real function (wifi_hal_nl80211_utils.c:5019-5041);
 * malloc / os_free are counted; the hostapd macros (WPA_PUT_LE*, MACSTR / MAC2STR, WNM_* / WLAN_EID_* constants) are the hostapd definitions; the *_print macros go to the log sink hwr_print.
 * Renamed hwr_sg_wifi_hal_setBTMRequest.
 */
#include "hwr_wbt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BIT(n) (1U << (n))
#define ETH_ALEN 6
#define WLAN_EID_NEIGHBOR_REPORT 52
#define WNM_NEIGHBOR_BSS_TRANSITION_CANDIDATE 3
#define WNM_BSS_TM_REQ_PREF_CAND_LIST_INCLUDED BIT(0)
#define WNM_BSS_TM_REQ_BSS_TERMINATION_INCLUDED BIT(3)
#define WNM_BSS_TM_REQ_ESS_DISASSOC_IMMINENT BIT(4)
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define WPA_PUT_LE16(a, val) do { (a)[1] = ((uint16_t)(val)) >> 8; (a)[0] = ((uint16_t)(val)) & 0xff; } while (0)
#define WPA_PUT_LE32(a, val) do { (a)[3] = (u8)((((uint32_t)(val)) >> 24) & 0xff); (a)[2] = (u8)((((uint32_t)(val)) >> 16) & 0xff); (a)[1] = (u8)((((uint32_t)(val)) >> 8) & 0xff); (a)[0] = (u8)(((uint32_t)(val)) & 0xff); } while (0)
#define WPA_PUT_LE64(a, val) do { (a)[7] = (u8)(((uint64_t)(val)) >> 56); (a)[6] = (u8)(((uint64_t)(val)) >> 48); (a)[5] = (u8)(((uint64_t)(val)) >> 40); (a)[4] = (u8)(((uint64_t)(val)) >> 32); (a)[3] = (u8)(((uint64_t)(val)) >> 24); (a)[2] = (u8)(((uint64_t)(val)) >> 16); (a)[1] = (u8)(((uint64_t)(val)) >> 8); (a)[0] = (u8)(((uint64_t)(val)) >> 0); } while (0)
#define os_memcpy memcpy
/* src/wifi_hal.c:2628-2634 */
#define _IS_INVALID_ARG(expr) ({ \
    bool __not_valid = (expr); \
    if (__not_valid) { \
        wifi_hal_error_print("%s:%d: Invalid argument; " #expr "\n", __func__, __LINE__); \
    } \
    __not_valid; \
})

hwr_wbt_world_t hwr_wbt_world;

/* counted allocator (defined before malloc / os_free are redirected to it) */
static void *hwr_wbt_malloc(size_t n)
{
    hwr_wbt_world.malloc_calls++;
    if (hwr_wbt_world.malloc_fail_at && hwr_wbt_world.malloc_calls == hwr_wbt_world.malloc_fail_at) return NULL;
    hwr_wbt_world.live_alloc++;
    return calloc(1, n);
}
static void hwr_wbt_free(void *p)
{
    if (p) hwr_wbt_world.live_alloc--;
    free(p);
}

#define wifi_hal_dbg_print(format, ...)          hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)        hwr_print(1, format, ##__VA_ARGS__)
#define g_wifi_hal hwr_wbt_world.hal
#define malloc hwr_wbt_malloc
#define os_free hwr_wbt_free
#define get_interface_by_vap_index hwr_wbt_get_interface_by_vap_index
#define ap_get_sta hwr_wbt_ap_get_sta
#define wifi_wnm_send_bss_tm_req hwr_wbt_wifi_wnm_send_bss_tm_req
#define wifi_strncpy hwr_wbt_wifi_strncpy
#define wifi_hal_setBTMRequest hwr_sg_wifi_hal_setBTMRequest

extern "C" {
wifi_interface_info_t *get_interface_by_vap_index(unsigned int vap_index)
{
    return vap_index < HWR_WBT_MAXI ? &hwr_wbt_world.ifs[vap_index] : NULL;
}
struct sta_info *ap_get_sta(struct hostapd_data *hapd, const u8 *sta)
{
    if (hwr_wbt_world.no_sta || memcmp(sta, hwr_wbt_world.known_mac, 6) != 0) return NULL;
    return &hwr_wbt_world.sta;
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
int wifi_wnm_send_bss_tm_req(struct wifi_interface_info_t *interface, struct sta_info *sta, u8 dialog_token, u8 req_mode, int disassoc_timer, u8 valid_int,
    const u8 *bss_term_dur, const char *url, const u8 *nei_rep, size_t nei_rep_len, const u8 *mbo_attrs, size_t mbo_len)
{
    hwr_wbt_world_t *w = &hwr_wbt_world;
    w->send_calls++; w->send_sta = sta; w->send_token = dialog_token; w->send_mode = req_mode; w->send_timer = disassoc_timer; w->send_valid = valid_int;
    memcpy(w->send_term, bss_term_dur, 12);
    w->send_url_null = url == NULL;
    if (url) snprintf(w->send_url, sizeof(w->send_url), "%s", url);
    w->send_nei_null = nei_rep == NULL; w->send_nei_len = (int)nei_rep_len;
    if (nei_rep && nei_rep_len <= HWR_WBT_NEI_MAX) memcpy(w->send_nei, nei_rep, nei_rep_len);
    w->mutex_held_at_send = pthread_mutex_trylock(&hwr_wbt_world.hal.hapd_lock) != 0;
    return w->send_ret;
}

/* --- wifi_hal.c:3718-3898 --- */
#define MAX_TOKENS             255

/* length: 13 for basic neighbor report + 3 for preference subelement */
#define NEI_LEN     (ETH_ALEN + 4 + 1 + 1 + 1 + 3)
#define NEIREP_LEN  (MAX_CANDIDATES * (2 + NEI_LEN))

static int build_candidates_list(const wifi_BTMRequest_t *request, u8 *nei_rep, size_t nei_rep_len)
{
    unsigned i;
    const wifi_NeighborReport_t *candidate;
    u8 *nei_pos = nei_rep;

    if (request->numCandidates >= MAX_CANDIDATES) {
        wifi_hal_error_print("%s:%d: [BTM] Wrong number of candidates (%u)\n", __func__, __LINE__, request->numCandidates);
        return -1;
    }

    for (i = 0, candidate = request->candidates; i < request->numCandidates; i++, candidate++)
    {
        u8 cand_pref;

        if (nei_pos + (2 + NEI_LEN) > nei_rep + nei_rep_len) {
            wifi_hal_error_print("%s:%d: [BTM] Not enough room for additional neighbor\n", __func__, __LINE__);
            return -1;
        }

    // - header: 2 bytes
        *nei_pos++ = WLAN_EID_NEIGHBOR_REPORT;
    // - length to be filled in
        *nei_pos++ = NEI_LEN;

    // - BSSID: 6 (ETH_ALEN) bytes
        os_memcpy(nei_pos, candidate->bssid, ETH_ALEN);
        nei_pos += ETH_ALEN;

    // - BSSID Information: 4 bytes
        WPA_PUT_LE32(nei_pos, candidate->info);
        nei_pos += 4;

    // - Operating Class: 1 byte
        *nei_pos++ = candidate->opClass;

    // - Channel Number: 1 byte
        *nei_pos++ = candidate->channel;

    // - PHY Type: 1 byte
        *nei_pos++ = candidate->phyTable;

    // - Priority: 3 bytes
        cand_pref = 255 - i;
        *nei_pos++ = WNM_NEIGHBOR_BSS_TRANSITION_CANDIDATE;
        *nei_pos++ = 1;
        *nei_pos++ = cand_pref;
    }

    return nei_pos - nei_rep;
}

/* See 9.6.14.9 BSS Transition Management Request.
   NOTE: peerMac expects MAC address in 6-byte binary format
*/
INT wifi_hal_setBTMRequest(UINT apIndex, mac_address_t peerMac, wifi_BTMRequest_t *request)
{
    wifi_interface_info_t *interface;
    u8 requestMode = request->requestMode;
    struct sta_info *sta = NULL;
    u8 bss_term_dur[12] = {0};
    char *url = NULL;
    int ret_token = -1;
    u8 *nei_rep = NULL;
    int nei_len = 0;

    // - verify input params
    if (_IS_INVALID_ARG(peerMac == NULL)) {
        return WIFI_HAL_INVALID_ARGUMENTS;
    }

    if (_IS_INVALID_ARG(request == NULL)) {
        return WIFI_HAL_INVALID_ARGUMENTS;
    }

    interface = get_interface_by_vap_index(apIndex);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: [BTM] BTM request: interface for ap index:%u not found\n", __func__, __LINE__, apIndex);
        return WIFI_HAL_ERROR;
    }

    if (interface->vap_info.vap_mode != wifi_vap_mode_ap) {
        wifi_hal_error_print("%s:%d: [BTM] BTM request: interface with ap index:%u not in AP mode\n", __func__, __LINE__, apIndex);
        return WIFI_HAL_ERROR;
    }

    // Get sta
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    sta = ap_get_sta(&interface->u.ap.hapd, peerMac);
    if (sta == NULL) {
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
        wifi_hal_error_print("%s:%d: [BTM] BTM request: station " MACSTR " not found for BSS TM Request message\n", __func__, __LINE__, MAC2STR(peerMac));
        return WIFI_HAL_ERROR;
    }

    /// - flag WNM_BSS_TM_REQ_BSS_TERMINATION_INCLUDED:
    if (!request->termDuration.duration) {
        // - if no duration, remove flag WNM_BSS_TM_REQ_BSS_TERMINATION_INCLUDED
        requestMode &= ~WNM_BSS_TM_REQ_BSS_TERMINATION_INCLUDED;
    }

    if (requestMode & WNM_BSS_TM_REQ_BSS_TERMINATION_INCLUDED) {
        bss_term_dur[0] = 4; /* Subelement ID */
        bss_term_dur[1] = 10; /* Length */
        WPA_PUT_LE64(&bss_term_dur[2], request->termDuration.tsf);
        WPA_PUT_LE16(&bss_term_dur[10], (short)request->termDuration.duration);
        wifi_hal_dbg_print("%s:%d: [BTM]  - WNM_BSS_TM_REQ_BSS_TERMINATION_INCLUDED, tsf:0x%0lX, dur:%u\n", __func__, __LINE__,
            request->termDuration.tsf, request->termDuration.duration);
    }

    /// - candidates list:
    if (requestMode & WNM_BSS_TM_REQ_PREF_CAND_LIST_INCLUDED) {
        nei_rep = (u8*) malloc(NEIREP_LEN);
        if (!nei_rep) {
            wifi_hal_error_print("%s:%d: [BTM] BTM request: Cannot allocate memory\n", __func__, __LINE__);
            goto exit;
        }
        nei_len = build_candidates_list(request, nei_rep, NEIREP_LEN);
        if (nei_len < 0) {
            wifi_hal_error_print("%s:%d: [BTM] BTM request: Cannot build candidates list\n", __func__, __LINE__);
            goto exit;
        }
        if (nei_len == 0) {
            requestMode &= ~WNM_BSS_TM_REQ_PREF_CAND_LIST_INCLUDED;
        }
    }

    // - after all checks:
    if (requestMode & WNM_BSS_TM_REQ_PREF_CAND_LIST_INCLUDED) {
        wifi_hal_dbg_print("%s:%d: [BTM]  - WNM_BSS_TM_REQ_BSS_TERMINATION_INCLUDED, nei_len=%d\n", __func__, __LINE__, nei_len);
    }

    /// - flag WNM_BSS_TM_REQ_ESS_DISASSOC_IMMINENT:
    if (!request->urlLen || !request->url[0]) {
        // - if no URL specified, remove flag WNM_BSS_TM_REQ_ESS_DISASSOC_IMMINENT
        requestMode &= ~WNM_BSS_TM_REQ_ESS_DISASSOC_IMMINENT;
    }

    /// - url:
    if (requestMode & WNM_BSS_TM_REQ_ESS_DISASSOC_IMMINENT) {
        url = (char*) malloc(request->urlLen + 1);
        if (url == NULL) {
            wifi_hal_error_print("%s:%d: [BTM] BTM request: Cannot allocate memory\n", __func__, __LINE__);
            goto exit;
        }
        wifi_strncpy(url, request->urlLen + 1, request->url, request->urlLen);
        wifi_hal_dbg_print("%s:%d: [BTM]  - WNM_BSS_TM_REQ_ESS_DISASSOC_IMMINENT, url:'%s'\n", __func__, __LINE__, url);
    }

    // - interface->u.ap.hapd has to be locked by mutex g_wifi_hal.hapd_lock
    ret_token = wifi_wnm_send_bss_tm_req(interface, sta,
                request->token,
                requestMode,
                (int)request->timer,
                (int)request->validityInterval,
                bss_term_dur,
                url,
                nei_len ? nei_rep : NULL, nei_len,
                NULL, 0);

    /*
        if dialog_token (request->token) was specifed as 0, wnm_send_bss_tm_req() returns value based on interface->bss_transition_token.
        So, probably, need to update this field with the returned value:
    */
    wifi_hal_dbg_print("%s:%d: [BTM] ret_token: %d\n", __func__, __LINE__, ret_token);
    if ((ret_token > 0) && (request->token == 0)) {
        request->token = ret_token;
    }

exit:
    os_free(nei_rep);
    os_free(url);
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    return ret_token < 0 ? WIFI_HAL_ERROR : WIFI_HAL_SUCCESS;
}
}
