/*
 * HANDLER: em_client_stats_store
 *
 * Copied VERBATIM from OneWifi source/apps/em/wifi_em.c. Local arrays:
 *   - mac_addr_str_t mac_str, bss_str (char[18]) : bounded to_mac_str().
 *   - unsigned char key[64]                      : snprintf(key,64,"%s@%s",..)
 *     of two 17-char mac strings -> 35 chars, comfortably within 64.
 * All three are fixed-size internal stack arrays (ASan stack redzones). radio_index
 * is validated (< MAX_NUM_RADIOS); the vap loop is bounded by
 * MAX_NUM_VAP_PER_RADIO; arr_vap_index is set only from that loop. No index
 * can run past an array and the key cannot overflow -> SAFE.
 *
 * Scaffolding (NOT under test): getVapInfo / to_mac_str are stubbed; hash_map_get
 * / hash_map_put are #define-redirected to a local single-entry store (frees
 * the strdup'd key the handler passes). Driven by the ecs_* globals.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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
/* wifi_associated_dev3_timestamp_t now comes from common.h */

/* --- scaffolding stubs --- */
static char *to_mac_str(mac_address_t mac, mac_addr_str_t key)
{
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}
static wifi_vap_info_t ecs_vap;
static wifi_vap_info_t *getVapInfo(unsigned int vap_index)
{
    (void)vap_index;
    if (ecs_getvap_null) return NULL;
    unsigned char b[6] = {0x90, 0x91, 0x92, 0x93, 0x94, 0x95};
    memcpy(ecs_vap.u.bss_info.bssid, b, 6);
    return &ecs_vap;
}

/* local single-entry hash map (isolates from the global one) */
static char  ecs_store_key[64];
static void *ecs_store_val;
static int   ecs_has_entry;
static void *ecs_hmget(void *m, const char *k) { (void)m; return (ecs_has_entry && strcmp(ecs_store_key, k) == 0) ? ecs_store_val : NULL; }
static int   ecs_hmput(void *m, char *k, void *d) { (void)m; snprintf(ecs_store_key, 64, "%s", k); ecs_store_val = d; ecs_has_entry = 1; free(k); return 0; }
#define hash_map_get(m, k)     ecs_hmget((m), (k))
#define hash_map_put(m, k, d)  ecs_hmput((m), (k), (d))

/* reset/prepopulate helpers used by the constructor */
void ecs_store_reset(void) { if (ecs_store_val) free(ecs_store_val); ecs_store_val = NULL; ecs_has_entry = 0; ecs_store_key[0] = 0; }
void ecs_store_prepopulate(const char *key) { ecs_store_reset(); snprintf(ecs_store_key, 64, "%s", key); ecs_store_val = calloc(1, sizeof(wifi_associated_dev3_timestamp_t)); ecs_has_entry = 1; }

/* ================= VERBATIM from wifi_em.c ================= */
int em_client_stats_store(unsigned int radio_index, unsigned int vap_index, int sta_cnt,
    wifi_associated_dev3_t *dev3, struct timespec *timestamp)
{
    wifi_associated_dev3_timestamp_t *stats = NULL;
    wifi_associated_dev3_timestamp_t *new_stats = NULL;
    mac_addr_str_t mac_str = { 0 }, bss_str = { 0 };
    unsigned char key[64] = { 0 };
    int arr_vap_index = -1;
    unsigned int i = 0;
    wifi_vap_info_t *vap_info = NULL;

    if (dev3 == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d null stats=%d\n", __func__, __LINE__,
            radio_index);
        return RETURN_ERR;
    }

    if (radio_index >= MAX_NUM_RADIOS) {
        wifi_util_error_print(WIFI_EM, "%s:%d invalid radio_index=%d\n", __func__, __LINE__,
            radio_index);
        return RETURN_ERR;
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
        wifi_util_dbg_print(WIFI_EM, "%s:%d Vap map not found for vapIndex: %d\n",
            __func__, __LINE__, vap_index);
        return RETURN_ERR;
    }

    em_ap_metrics_report_cache.radio_report[radio_index].ap_data[arr_vap_index].sta_count = sta_cnt;

    vap_info = getVapInfo(vap_index);
    if (vap_info == NULL) {
        wifi_util_dbg_print(WIFI_EM, "%s:%d Vap not found for vap index:%d\n",
            __func__, __LINE__, vap_index);
        return RETURN_ERR;
    }
    to_mac_str(vap_info->u.bss_info.bssid, bss_str);
    to_mac_str(dev3->cli_MACAddress, mac_str);
    snprintf(key, 64, "%s@%s", bss_str, mac_str);
    wifi_util_dbg_print(WIFI_EM, "%s:%d key while updating cache is =%s and arr_vap_index:%d\n",
        __func__, __LINE__, key, arr_vap_index);

    stats = (wifi_associated_dev3_timestamp_t *)hash_map_get(
        em_ap_metrics_report_cache.radio_report[radio_index].ap_data[arr_vap_index].client_stats_map, key);
    if (stats == NULL) {
        // add new entries
        new_stats = (wifi_associated_dev3_timestamp_t *)calloc(1, sizeof(wifi_associated_dev3_timestamp_t));
        if (new_stats == NULL) {
            wifi_util_error_print(WIFI_EM, "%s:%d null stats=%d\n", __func__, __LINE__,
                radio_index);
            return RETURN_ERR;
        }
        memcpy(&new_stats->associated_dev3, dev3, sizeof(wifi_associated_dev3_t));
        if (timestamp != NULL) {
            new_stats->last_update_time = *timestamp;
        }

        hash_map_put(em_ap_metrics_report_cache.radio_report[radio_index].ap_data[arr_vap_index].client_stats_map,
            strdup(key), new_stats);
    } else {
        memcpy(&stats->associated_dev3, dev3, sizeof(wifi_associated_dev3_t));
        if (timestamp != NULL) {
            stats->last_update_time = *timestamp;
        }
    }

    wifi_util_dbg_print(WIFI_EM, "%s:%d added sample for radio_index=%d, vap_index=%d, client=%s\n",
        __func__, __LINE__, radio_index, vap_index, mac_str);

    return RETURN_OK;
}
