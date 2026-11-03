/*
 * HANDLER: em_send_action_frame
 *
 * Copied VERBATIM from OneWifi source/apps/em/wifi_em.c (only "static"
 * dropped). Local arrays:
 *   - char country[8]      : get_coutry_str_from_code() (2-3 char code).
 *   - char client_mac[32]  : bounded to_mac_str (18 chars).
 *   - char bssid_str[32]   : bounded to_mac_str (18 chars).
 * The vap/radio loops are bounded by num_of_radios and num_vaps; ap_index is
 * validated before the radio lookup. No array can be overrun -> SAFE.
 *
 * Scaffolding (NOT under test): get_wifimgr_obj / getNumberRadios /
 * get_wifidb_vap_map / get_radio_index_for_vap_index / get_wifidb_radio_map /
 * to_mac_str / get_coutry_str_from_code / country_to_global_op_class /
 * wifi_hal_setRMBeaconRequest are stubbed, driven by the esaf_* globals.
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
#define wifi_util_error_print(m, ...) do {} while (0)
#endif
#ifndef UCHAR
#define UCHAR unsigned char
#endif
#define WIFI_HAL_SUCCESS 0

/* --- scaffolding stubs driven by esaf_* globals --- */
static wifi_mgr_t *get_wifimgr_obj(void) { return (wifi_mgr_t *)esaf_mgr_buf; }
static unsigned int getNumberRadios(void) { return (unsigned int)esaf_num_radios; }
static void *get_wifidb_vap_map(int i) { return esaf_vap_present[i] ? (void *)&esaf_vap_maps[i] : NULL; }
static int get_radio_index_for_vap_index(wifi_platform_property_t *wp, int ap_index) { (void)wp; (void)ap_index; return esaf_radio_index; }
static void *get_wifidb_radio_map(int radio_index) { (void)radio_index; return esaf_radio_null ? NULL : (void *)&esaf_radio_oper; }
static char *to_mac_str(mac_address_t mac, char *key)
{
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return key;
}
static int get_coutry_str_from_code(unsigned int code, char *country)
{
    (void)code;
    if (esaf_country_fail) return RETURN_ERR;
    snprintf(country, 8, "US");
    return RETURN_OK;
}
static unsigned int country_to_global_op_class(const char *country, unsigned int op_class) { (void)country; return op_class; }
static int wifi_hal_setRMBeaconRequest(int ap_index, unsigned char *sta_mac, wifi_BeaconRequest_t *params, UCHAR *out_dialog)
{
    (void)ap_index; (void)sta_mac; (void)params; (void)out_dialog;
    esaf_send_calls++;
    return esaf_send_fail ? 1 : WIFI_HAL_SUCCESS;
}

/* ================= VERBATIM from wifi_em.c (static dropped) ================= */
int em_send_action_frame(void *data)
{
    unsigned int op_class;
    char country[8] = { 0 };
    char client_mac[32];
    char bssid_str[32];
    unsigned int global_op_class;
    UCHAR out_dialog = rand() % 256;
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();
    wifi_platform_property_t *wifi_prop = &wifi_mgr->hal_cap.wifi_prop;
    unsigned int num_of_radios = getNumberRadios();
    wifi_vap_info_map_t *vap_map;

    beacon_query_params_t *query = (beacon_query_params_t *)data;
    wifi_BeaconRequest_t *params = &query->data;
    int ap_index = RETURN_ERR;

    for (unsigned int i = 0; i < num_of_radios; i++) {
        vap_map = (wifi_vap_info_map_t *)get_wifidb_vap_map(i);
        if (vap_map == NULL) {
            continue;
        }

        for (int j = 0; j < vap_map->num_vaps; j++) {
            if (memcmp(params->bssid, vap_map->vap_array[j].u.bss_info.bssid, sizeof(mac_addr_t)) ==
                0) {
                ap_index = vap_map->vap_array[j].vap_index;
                break;
            }
            if (memcmp(params->bssid,
                    vap_map->vap_array[j].u.bss_info.mld_info.common_info.mld_addr,
                    sizeof(mac_addr_t)) == 0) {
                ap_index = vap_map->vap_array[j].vap_index;
                break;
            }
        }

        if (ap_index != RETURN_ERR) {
            break;
        }
    }

    to_mac_str((unsigned char *)query->sta_mac, client_mac);
    to_mac_str((unsigned char *)params->bssid, bssid_str);
    wifi_util_dbg_print(WIFI_EM,
        "%s:%d: Sending beacon query action frame for mac %s with ap_index %d bssid:%s\n", __func__,
        __LINE__, client_mac, ap_index, bssid_str);
    if (ap_index == RETURN_ERR) {
        wifi_util_error_print(WIFI_EM, "%s:%d Failed to resolve ap_index for bssid:%s\n", __func__,
            __LINE__, bssid_str);
        return RETURN_ERR;
    }

    unsigned int radio_index = get_radio_index_for_vap_index(wifi_prop, ap_index);
    wifi_radio_operationParam_t *radio_oper_param =
        (wifi_radio_operationParam_t *)get_wifidb_radio_map(radio_index);

    if (radio_oper_param == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d Unable to get radio params with radio_index:%d\n",
            __func__, __LINE__, radio_index);
        return RETURN_ERR;
    }

    if (RETURN_OK != get_coutry_str_from_code(radio_oper_param->countryCode, country)) {
        wifi_util_error_print(WIFI_EM, "%s:%d Unable to read country code\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    op_class = radio_oper_param->operatingClass;
    global_op_class = country_to_global_op_class(country, op_class);

    if (params->opClass != 0) {
        unsigned int normalized = country_to_global_op_class(country, params->opClass);
        if (normalized != params->opClass) {
            params->opClass = normalized;
        }
    }

    bool chan_is_2g = (params->channel >= 1 && params->channel <= 14);
    bool opclass_is_2g = (params->opClass >= 81 && params->opClass <= 84);
    bool opclass_is_5g = (params->opClass >= 115 && params->opClass <= 130);
    bool band_mismatch = (chan_is_2g && opclass_is_5g) || (!chan_is_2g && opclass_is_2g) ||
        (params->opClass != 0 && !opclass_is_2g && !opclass_is_5g && params->opClass < 131);
    if (band_mismatch) {
        params->opClass = global_op_class;
        params->channel = radio_oper_param->channel;
    }

    params->duration = 200;

    if (params->channel == 255) {
        if (params->channelReportPresent) {
            params->opClass = params->channelReport.opClass;
        } else {
            params->opClass = global_op_class;
            params->channel = radio_oper_param->channel;
        }
    }

    if (wifi_hal_setRMBeaconRequest(ap_index, query->sta_mac, params, &out_dialog) !=
        WIFI_HAL_SUCCESS) {
        wifi_util_error_print(WIFI_EM, "%s:%d: Failed to send RM Beacon Request (ap_index=%d)\n",
            __func__, __LINE__, ap_index);
        return RETURN_ERR;
    }

    return 0;
}
