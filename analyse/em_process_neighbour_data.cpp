/*
 * HANDLER: em_process_neighbour_data
 *
 * Copied VERBATIM from OneWifi source/apps/em/wifi_em.c (only "static"
 * dropped). Local arrays:
 *   - channel_scan_response_t scan_response : filled by em_prepare_scan_response_data.
 *   - char local_ssids[MAX_LOCAL_SSIDS][MAX_SSID_LEN] (16 x 33) : filled by
 *     get_vap_ssid_list() and read by ssid_in_local_list().
 * The BTM neighbor copy is guarded by btm->num_neighbors < EM_MAX_NEIGHBORS
 * (btm->neighbors is [16]); local_ssids is written only by get_vap_ssid_list
 * (bounded to MAX_LOCAL_SSIDS). No index in this function runs past an array
 * -> SAFE.
 *
 * Scaffolding (NOT under test): get_wifimgr_obj / get_vap_ssid_list /
 * ssid_in_local_list / to_mac_str / calculate_preference / compare_pref /
 * push_event_to_ctrl_queue / em_stop_neighbor_scan are stubbed;
 * em_prepare_scan_response_data and em_publish_stats_data are #define-redirected
 * to local stubs so the real symbols (their own TUs) are not redefined.
 * Driven by the epnd_* globals.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "common.h"

#ifndef RETURN_OK
#define RETURN_OK  0
#endif
#ifndef RETURN_ERR
#define RETURN_ERR (-1)
#endif
#define WIFI_EM 0
#ifndef wifi_util_dbg_print
#define wifi_util_dbg_print(m, ...)   do {} while (0)
#define wifi_util_info_print(m, ...)  do {} while (0)
#define wifi_util_error_print(m, ...) do {} while (0)
#endif
#define wifi_event_type_command    1
#define wifi_event_type_send_btm_req 2
/* UINT comes from common.h */

/* --- scaffolding stubs driven by epnd_* globals --- */
static wifi_mgr_t *get_wifimgr_obj(void) { return epnd_mgr_null ? NULL : (wifi_mgr_t *)epnd_mgr_buf; }

static int epnd_prepare(wifi_provider_response_t *resp, channel_scan_response_t *sr)
{
    (void)resp;
    if (epnd_prepare_fail) return RETURN_ERR;
    memset(sr, 0, sizeof(*sr));
    sr->num_results = epnd_num_results;
    for (int r = 0; r < epnd_num_results && r < EM_MAX_RESULTS; r++) {
        sr->results[r].operating_class = 115;
        sr->results[r].channel = 36 + r;
        sr->results[r].noise = -90;
        sr->results[r].utilization = 20;
        sr->results[r].num_neighbors = epnd_num_neighbors;
        for (int n = 0; n < epnd_num_neighbors && n < EM_MAX_NEIGHBORS; n++) {
            snprintf(sr->results[r].neighbors[n].ssid, sizeof(ssid_t), "Net%d", n);
            sr->results[r].neighbors[n].signal_strength = -55;
            snprintf(sr->results[r].neighbors[n].channel_bandwidth, EM_MAX_CHANNEL_BW_LEN, "20MHz");
        }
    }
    return RETURN_OK;
}
#define em_prepare_scan_response_data(r, s)  epnd_prepare((r), (s))

static int epnd_publish(channel_scan_response_t *sr) { (void)sr; epnd_publish_calls++; return epnd_publish_fail ? RETURN_ERR : RETURN_OK; }
#define em_publish_stats_data(s)  epnd_publish((s))

static int get_vap_ssid_list(char ssid_list[MAX_LOCAL_SSIDS][MAX_SSID_LEN])
{
    int n = epnd_vap_ssid_count;
    if (n > MAX_LOCAL_SSIDS) n = MAX_LOCAL_SSIDS;
    for (int i = 0; i < n; i++) snprintf(ssid_list[i], MAX_SSID_LEN, "Net%d", i);
    return n;
}
static bool ssid_in_local_list(const char *ssid, char list[MAX_LOCAL_SSIDS][MAX_SSID_LEN], int count)
{
    if (epnd_ssid_match_all) return true;
    for (int i = 0; i < count; i++) if (strcmp(ssid, list[i]) == 0) return true;
    return false;
}
static char *to_mac_str(mac_address_t mac, char *key)
{
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return key;
}
static int calculate_preference(wifi_neighbor_ap2_t *n) { return n ? (100 + n->ap_SignalStrength) : 0; }
static int compare_pref(const void *a, const void *b)
{
    const neighbor_with_opclass_t *x = (const neighbor_with_opclass_t *)a;
    const neighbor_with_opclass_t *y = (const neighbor_with_opclass_t *)b;
    return y->score - x->score;
}
static void push_event_to_ctrl_queue(void *data, unsigned int len, int t1, int t2, void *p)
{ (void)data; (void)len; (void)t1; (void)t2; (void)p; epnd_push_calls++; }
static void em_stop_neighbor_scan(wifi_provider_response_t *resp) { (void)resp; epnd_stop_calls++; }

/* ================= VERBATIM from wifi_em.c (static dropped) ================= */
int em_process_neighbour_data(wifi_provider_response_t *provider_response)
{
    channel_scan_response_t scan_response;
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();

    wifi_util_dbg_print(WIFI_EM, "%s:%d: Processing neighbour stats data\n", __func__, __LINE__);

    if (wifi_mgr == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d: wifi_mgr or chan_scan_data is NULL\n", __func__,
            __LINE__);
        return RETURN_ERR;
    }

    if (em_prepare_scan_response_data(provider_response, &scan_response) != RETURN_OK) {
        wifi_util_error_print(WIFI_EM, "%s:%d Prepare neighbour scan response failed\r\n", __func__,
            __LINE__);

        // If BTM is pending, send empty BTM request
        if (g_btm_pending_valid) {
            em_btm_req_ctrl_msg_t *btm = &g_pending_btm;
            btm->num_neighbors = 0;
            btm->neighbor_list_present = false;

            push_event_to_ctrl_queue(btm, sizeof(em_btm_req_ctrl_msg_t), wifi_event_type_command, wifi_event_type_send_btm_req, NULL);

            wifi_util_info_print(WIFI_EM, "%s:%d BTM Request sent with empty neighbor list (scan failed)\n",__func__, __LINE__);

            g_btm_pending_valid = false;
            return RETURN_OK;
        }
        return RETURN_ERR;
    }

    if (g_btm_pending_valid) {
        em_btm_req_ctrl_msg_t *btm = &g_pending_btm;
        char local_ssids[MAX_LOCAL_SSIDS][MAX_SSID_LEN];
        int local_ssid_count = get_vap_ssid_list(local_ssids);

        // Populate neighbors[]
        for (uint32_t i = 0; i < scan_response.num_results && btm->num_neighbors < EM_MAX_NEIGHBORS; i++) {
            channel_scan_result_t *res = &scan_response.results[i];

            for (UINT n_idx = 0; n_idx < res->num_neighbors && btm->num_neighbors < EM_MAX_NEIGHBORS; n_idx++) {
                neighbor_bss_t *bss = &res->neighbors[n_idx];

                if (!ssid_in_local_list(bss->ssid, local_ssids, local_ssid_count)) {
                    continue;
                }

                neighbor_with_opclass_t n_local;
                memset(&n_local, 0, sizeof(n_local));

                wifi_neighbor_ap2_t *n = &n_local.base;
                to_mac_str(bss->bssid, n->ap_BSSID);
                snprintf(n->ap_SSID, sizeof(n->ap_SSID), "%s", bss->ssid);
                n->ap_Channel = res->channel;
                n->ap_Noise = res->noise;
                n->ap_SignalStrength = bss->signal_strength;
                n->ap_ChannelUtilization = res->utilization;
                n_local.opClass = res->operating_class;
                snprintf(n->ap_OperatingChannelBandwidth, sizeof(n->ap_OperatingChannelBandwidth), "%s", bss->channel_bandwidth);
                n_local.score = calculate_preference(&n_local.base);
                btm->neighbors[btm->num_neighbors] = n_local;
                btm->num_neighbors++;
            }
        }

        btm->neighbor_list_present = (btm->num_neighbors > 0);

        if (btm->num_neighbors > 0) {
            g_pending_btm.request_mode = 0x01;
        }

        if (btm->num_neighbors > 0) {
            qsort(btm->neighbors, btm->num_neighbors, sizeof(neighbor_with_opclass_t), compare_pref);
        }

        // Push only the BTM request event
        push_event_to_ctrl_queue(btm, sizeof(em_btm_req_ctrl_msg_t), wifi_event_type_command, wifi_event_type_send_btm_req, NULL);

        wifi_util_info_print(WIFI_EM, "%s:%d BTM Request sent with %u neighbors\n", __func__, __LINE__, btm->num_neighbors);

        // Clear BTM pending state
        g_btm_pending_valid = false;

        // Stop scan explicitly if needed
        em_stop_neighbor_scan(provider_response);
        return RETURN_OK;
    }

    if (em_publish_stats_data(&scan_response) != RETURN_OK) {
        wifi_util_error_print(WIFI_EM, "%s:%d Publishing neighbour stats data failed\r\n", __func__,
            __LINE__);
        return RETURN_ERR;
    }

    em_stop_neighbor_scan(provider_response);

    return RETURN_OK;
}
