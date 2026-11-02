/*
 * HANDLER: assoc_client_response
 *
 * Copied VERBATIM from OneWifi source/apps/em/wifi_em.c. Local array:
 *   - char vap_name[32] : filled by convert_vap_index_to_name() (bounded).
 *
 * BUG under test: the copy into the fixed per-vap buffer
 *   client_assoc_stats[radio_index].client_assoc_data[vap_array_index].assoc_stats
 * (sta_data_t[BSS_MAX_NUM_STATIONS]) is
 *   memcpy(dst, provider_response->stat_pointer,
 *          sizeof(sta_data_t) * provider_response->stat_array_size);
 * with NO clamp of stat_array_size to BSS_MAX_NUM_STATIONS. A provider
 * response reporting more than BSS_MAX_NUM_STATIONS stations overruns
 * assoc_stats. (Separately, radio_index is taken straight from the response
 * and never checked against MAX_NUM_RADIOS before indexing client_assoc_stats.)
 *
 * Scaffolding (NOT under test): get_wifimgr_obj / convert_vap_index_to_name /
 * convert_vap_name_to_array_index / handle_ready_client_stats are stubbed and
 * driven by the acr_* globals.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

/* --- scaffolding stubs driven by acr_* globals --- */
static wifi_mgr_t *get_wifimgr_obj(void) { return (wifi_mgr_t *)acr_mgr_buf; }
static int convert_vap_index_to_name(wifi_platform_property_t *prop, unsigned int vap_index, char *vap_name)
{
    (void)prop;
    if (!acr_convert_name_ok) return RETURN_ERR;
    snprintf(vap_name, 32, "vap%u", vap_index);
    return RETURN_OK;
}
static int convert_vap_name_to_array_index(wifi_platform_property_t *prop, char *vap_name)
{
    (void)prop; (void)vap_name;
    return acr_vap_array_index;
}
static int handle_ready_client_stats(wifi_app_t *app, client_assoc_data_t *stats, size_t stats_num,
    unsigned int presence_mask, unsigned int radio_index, unsigned int vap_index,
    unsigned int app_info, unsigned int stat_array_size)
{
    (void)app; (void)stats; (void)stats_num; (void)presence_mask; (void)radio_index;
    (void)vap_index; (void)app_info; (void)stat_array_size;
    acr_ready_calls++;
    return RETURN_OK;
}

/* ================= VERBATIM from wifi_em.c ================= */
int assoc_client_response(wifi_app_t *app, wifi_provider_response_t *provider_response)
{
    unsigned int radio_index = 0;
    unsigned int vap_index = 0;
    int vap_array_index = 0;
    radio_index = provider_response->args.radio_index;
    vap_index = provider_response->args.vap_index;
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();
    char vap_name[32];

    wifi_util_info_print(WIFI_EM, "%s:%d: provider_response is for radio index: %d and vap index: %d\n",
         __func__, __LINE__, radio_index, vap_index);

    if (provider_response->stat_array_size <= 0) {
        wifi_util_error_print(WIFI_EM, "%s:%d: provider_response is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (radio_index >= MAX_NUM_RADIOS) {   /* FIX: bound the peer-supplied radio_index */
        wifi_util_error_print(WIFI_EM, "%s:%d: invalid radio_index: %d\n", __func__, __LINE__, radio_index);
        return RETURN_ERR;
    }

    if (convert_vap_index_to_name(&wifi_mgr->hal_cap.wifi_prop, vap_index, vap_name) != RETURN_OK) {
        wifi_util_error_print(WIFI_EM,
            "%s:%d: convert_vap_index_to_name failed for vap_index : %d\r\n", __func__, __LINE__,
            vap_index);
        return RETURN_ERR;
    }

    vap_array_index = convert_vap_name_to_array_index(&wifi_mgr->hal_cap.wifi_prop, vap_name);
    if (vap_array_index == -1) {
        wifi_util_error_print(WIFI_EM,
            "%s:%d: convert_vap_name_to_array_index failed for vap_name: %s\r\n", __func__,
            __LINE__, vap_name);
        return RETURN_ERR;
    }

    /* FIX: clamp the peer-supplied count to the fixed assoc_stats capacity */
    unsigned int num_stats = provider_response->stat_array_size;
    if (num_stats > BSS_MAX_NUM_STATIONS) {
        wifi_util_error_print(WIFI_EM, "%s:%d: stat_array_size %u exceeds %d, clamping\n",
            __func__, __LINE__, num_stats, BSS_MAX_NUM_STATIONS);
        num_stats = BSS_MAX_NUM_STATIONS;
    }
    memset(client_assoc_stats[radio_index].client_assoc_data[vap_array_index].assoc_stats, 0,
        sizeof(client_assoc_stats[radio_index].client_assoc_data[vap_array_index].assoc_stats));
    memcpy(client_assoc_stats[radio_index].client_assoc_data[vap_array_index].assoc_stats,
        provider_response->stat_pointer, (sizeof(sta_data_t) * num_stats));
    client_assoc_stats[radio_index].client_assoc_data[vap_array_index].stat_array_size =
        num_stats;
    client_assoc_stats[radio_index].assoc_stats_vap_presence_mask |= (1 << vap_index);

    wifi_util_dbg_print(WIFI_EM, "%s:%d: vap_index : %d client array size : %d \r\n", __func__,
        __LINE__, vap_index, provider_response->stat_array_size);

    if (client_assoc_stats[radio_index].assoc_stats_vap_presence_mask ==
            (client_assoc_stats[radio_index].req_stats_vap_mask & client_assoc_stats[radio_index].assoc_stats_vap_presence_mask)) {
        wifi_util_dbg_print(WIFI_EM, "%s:%d: push stats for radio_index : %d \r\n", __func__,
            __LINE__, radio_index);
        handle_ready_client_stats(app, client_assoc_stats[radio_index].client_assoc_data,
            MAX_NUM_VAP_PER_RADIO, client_assoc_stats[radio_index].assoc_stats_vap_presence_mask,
            radio_index, vap_index, provider_response->args.app_info,
            provider_response->stat_array_size);
        client_assoc_stats[radio_index].assoc_stats_vap_presence_mask = 0;
    }

    return RETURN_OK;
}
