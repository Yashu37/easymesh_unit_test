/*
 * HANDLER: em_handle_disassoc_device
 *
 * Copied VERBATIM from OneWifi source/apps/em/wifi_em.c (only "static"
 * dropped). Local arrays:
 *   - char client_mac[32]                 : bounded to_mac_str (18 chars).
 *   - unsigned char key[64]               : snprintf(key,64,"%s@%s",..) = 35 chars.
 *   - mac_addr_str_t sta_mac_str, bss_str : bounded to_mac_str.
 * radio_index is validated via get_radio_index_for_vap_index; arr_vap_index is
 * set only from the bounded MAX_NUM_VAP_PER_RADIO loop. No array can be
 * overrun -> SAFE.
 *
 * Scaffolding (NOT under test): get_wifictrl_obj / get_wifimgr_obj / getVapInfo
 * / to_mac_str are stubbed; get_radio_index_for_vap_index and hash_map_remove
 * are #define-redirected to local stubs. Driven by the hdd_* globals.
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

typedef struct { union { struct { unsigned char bssid[6]; } bss_info; } u; } wifi_vap_info_t;

/* --- scaffolding stubs driven by hdd_* globals --- */
static wifi_ctrl_t *get_wifictrl_obj(void) { return (wifi_ctrl_t *)hdd_ctrl_buf; }
static wifi_mgr_t  *get_wifimgr_obj(void) { return (wifi_mgr_t *)hdd_mgr_buf; }
static int hdd_get_radio(wifi_platform_property_t *wp, int vap_index) { (void)wp; (void)vap_index; return hdd_radio_index; }
#define get_radio_index_for_vap_index(wp, v)  hdd_get_radio((wp), (v))

static wifi_vap_info_t hdd_vap;
static wifi_vap_info_t *getVapInfo(int vap_index)
{
    (void)vap_index;
    if (hdd_vap_null) return NULL;
    unsigned char b[6] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15};
    memcpy(hdd_vap.u.bss_info.bssid, b, 6);
    return &hdd_vap;
}
static char *to_mac_str(mac_address_t mac, char *key)
{
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return key;
}

/* hash_map_remove: non-NULL map = client_stats_map (returns a static stats, the
 * function does NOT free it); NULL map = client_type_map (returns malloc'd, the
 * function frees it). */
static char hdd_stats_static[256];
static void *hdd_hmremove(void *map, const char *key)
{
    (void)key;
    if (map != NULL) return hdd_stats_present ? (void *)hdd_stats_static : NULL;
    return hdd_clitype_present ? calloc(1, sizeof(sta_client_info_t)) : NULL;
}
#define hash_map_remove(m, k)  hdd_hmremove((m), (k))
static struct { struct { void *client_type_map; } sta_client_type; } client_type_info;

/* ================= VERBATIM from wifi_em.c (static dropped) ================= */
int em_handle_disassoc_device(wifi_app_t *app, void *arg)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    assoc_dev_data_t *assoc_data = (assoc_dev_data_t *)arg;
    char client_mac[32];
    int vap_index = assoc_data->ap_index;
    unsigned char key[64] = { 0 };
    mac_addr_str_t sta_mac_str, bss_str;
    int i = 0;
    int radio_index = -1;
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();
    wifi_platform_property_t *wifi_prop = &wifi_mgr->hal_cap.wifi_prop;
    int arr_vap_index = -1;
    wifi_vap_info_t *vap_info = NULL;
    wifi_associated_dev3_timestamp_t *stats = NULL;
    (void)ctrl;

    wifi_util_dbg_print(WIFI_EM, "%s:%d : Sta disassoc event \n", __func__, __LINE__);

    radio_index = get_radio_index_for_vap_index(wifi_prop, vap_index);
    if (radio_index == RETURN_ERR) {
        wifi_util_dbg_print(WIFI_EM, "%s:%d could not find radio_index=%d for vap index = %d\n",
            __func__, __LINE__, radio_index, vap_index);
        return 0;
    }

    for (i = 0; i < MAX_NUM_VAP_PER_RADIO; i++) {
        if (vap_index == em_ap_metrics_report_cache.radio_report[radio_index].ap_data[i].vap_index) {
            arr_vap_index = i;
            break;
        } else {
            arr_vap_index = -1;
        }
    }

    if (arr_vap_index == -1) {
        wifi_util_dbg_print(WIFI_EM, "%s:%d Vap map not found\n",
            __func__, __LINE__, key);
        return RETURN_ERR;
    }

    vap_info = getVapInfo(vap_index);
    if (vap_info == NULL) {
        wifi_util_dbg_print(WIFI_EM, "%s:%d Vap not found for vap index:%d\n",
            __func__, __LINE__, vap_index);
        return RETURN_ERR;
    }
    to_mac_str(vap_info->u.bss_info.bssid, bss_str);
    to_mac_str(assoc_data->dev_stats.cli_MACAddress, sta_mac_str);
    snprintf((char *)key, 64, "%s@%s", bss_str, sta_mac_str);
    stats = (wifi_associated_dev3_timestamp_t *)hash_map_remove(
        em_ap_metrics_report_cache.radio_report[radio_index].ap_data[arr_vap_index].client_stats_map, (const char *)key);
    if (stats == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d: Sta Mac %s not present in hash map\n", __func__,
            __LINE__, sta_mac_str);
        return 0;
    }
    wifi_util_dbg_print(WIFI_EM, "%s:%d: Sta Mac %s disassociated\n", __func__,
        __LINE__, sta_mac_str);

    to_mac_str((unsigned char *)assoc_data->dev_stats.cli_MACAddress, client_mac);
    sta_client_info_t *t_sta_data = (sta_client_info_t *)hash_map_remove(
        client_type_info.sta_client_type.client_type_map, (const char *)client_mac);

    if (t_sta_data == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d: Mac %s not present in hash map\n", __func__,
            __LINE__, client_mac);
        return 0;
    }

    free(t_sta_data);

    return 0;
}
