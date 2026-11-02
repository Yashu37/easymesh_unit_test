/*
 * HANDLER: prepare_sta_lins_metrics_data
 *
 * Copied VERBATIM from OneWifi source/apps/em/wifi_em.c (only "static"
 * dropped). Local array:
 *   - mac_addr_str_t key (char[18]) : bounded to_mac_str(), used for the
 *     client_type_map lookup.
 * All writes go into the caller's `data` (per_sta_metrics_t) at fixed index
 * [0] (num_bssid is set to 1 and STA_MAX_BSS_ASSOCIATIONS == 1), and the
 * client_type copy is a strncpy bounded by sizeof(data->client_type)-1 with an
 * explicit NUL. key[18] is an internal stack array (ASan redzones). NULL args
 * and a missing vap are rejected -> SAFE.
 *
 * Scaffolding (NOT under test): getVapInfo / to_mac_str / em_rssi_to_rcpi are
 * stubbed; hash_map_get is #define-redirected to a local stub returning the
 * configured client-type entry. Driven by the psl_* globals.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
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
#define wifi_util_error_print(m, ...) do {} while (0)
#endif

typedef struct { union { struct { unsigned char bssid[6]; } bss_info; } u; } wifi_vap_info_t;

/* --- scaffolding stubs driven by psl_* globals --- */
static char *to_mac_str(mac_address_t mac, mac_addr_str_t key)
{
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}
static wifi_vap_info_t psl_vap;
static wifi_vap_info_t *getVapInfo(unsigned int vap_index)
{
    (void)vap_index;
    if (psl_getvap_null) return NULL;
    unsigned char b[6] = {0x70, 0x71, 0x72, 0x73, 0x74, 0x75};
    memcpy(psl_vap.u.bss_info.bssid, b, 6);
    return &psl_vap;
}
static unsigned int em_rssi_to_rcpi(int rssi) { return (unsigned int)((rssi + 110) * 2); }

/* client-type map lookup (local, isolates from the global hash map) */
static sta_client_info_t psl_cli;
static void *psl_hmget(void *m, const char *k) { (void)m; (void)k; return psl_has_clitype ? (void *)&psl_cli : NULL; }
#define hash_map_get(m, k)  psl_hmget((m), (k))
static struct { struct { void *client_type_map; } sta_client_type; } client_type_info;
void psl_set_clitype(const char *s) { snprintf((char *)psl_cli.client_type, sizeof(psl_cli.client_type), "%s", s); }

/* ================= VERBATIM from wifi_em.c (static dropped) ================= */
int prepare_sta_lins_metrics_data(per_sta_metrics_t *data, wifi_associated_dev3_timestamp_t *stats,
    unsigned int vap_index)
{
    sta_client_info_t *cli_data = NULL;
    mac_addr_str_t key = { 0 };
    wifi_vap_info_t *vap_info = NULL;
    struct timespec now;
    struct timespec diff;
    uint32_t delta_ms = 0;

    if ((data == NULL) || (stats == NULL)) {
        wifi_util_error_print(WIFI_EM, "%s:%d Invalid args for encode stats\n",
            __func__, __LINE__);
        return RETURN_ERR;
    }

    vap_info = getVapInfo(vap_index);
    if (vap_info == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d Vap not found\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (stats->last_update_time.tv_sec != 0) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (((long)now.tv_nsec - (long)stats->last_update_time.tv_nsec) < 0) {
                diff.tv_sec = now.tv_sec - stats->last_update_time.tv_sec - 1;
                diff.tv_nsec = now.tv_nsec - stats->last_update_time.tv_nsec + 1000000000L;
        } else {
            diff.tv_sec = now.tv_sec - stats->last_update_time.tv_sec;
            diff.tv_nsec = now.tv_nsec - stats->last_update_time.tv_nsec;
        }
        delta_ms = ((uint64_t)diff.tv_sec * 1000) + (diff.tv_nsec / 1000000);
    } else {
        delta_ms = 0;
    }

    // Associated STA Link Metrics
    memcpy(data->sta_mac, stats->associated_dev3.cli_MACAddress, sizeof(mac_address_t));
    // Retrive client type info
    to_mac_str(stats->associated_dev3.cli_MACAddress, key);
    cli_data = (sta_client_info_t *)hash_map_get(client_type_info.sta_client_type.client_type_map, key);
    if (cli_data != NULL) {
        strncpy((char *)data->client_type, (const char *)cli_data->client_type, sizeof(data->client_type) - 1);
        data->client_type[sizeof(data->client_type) - 1] = '\0';
    }

    data->assoc_sta_link_metrics.num_bssid = 1; // must be changed for STA multiple associations
    memcpy(data->assoc_sta_link_metrics.assoc_sta_link_metrics_data[0].bssid,
        vap_info->u.bss_info.bssid, sizeof(mac_address_t));
    data->assoc_sta_link_metrics.assoc_sta_link_metrics_data[0].time_delta = delta_ms;
    data->assoc_sta_link_metrics.assoc_sta_link_metrics_data[0].est_mac_rate_down =
        (stats->associated_dev3.cli_LastDataDownlinkRate);
    data->assoc_sta_link_metrics.assoc_sta_link_metrics_data[0].est_mac_rate_up =
        (stats->associated_dev3.cli_LastDataUplinkRate);
    data->assoc_sta_link_metrics.assoc_sta_link_metrics_data[0].rcpi = em_rssi_to_rcpi(
        stats->associated_dev3.cli_RSSI);

    // Associated STA Extended Link Metrics
    data->assoc_sta_ext_link_metrics.num_bssid = 1; // must be changed for STA multiple associations
    memcpy(data->assoc_sta_ext_link_metrics.assoc_sta_ext_link_metrics_data[0].bssid,
        vap_info->u.bss_info.bssid, sizeof(mac_address_t));
    data->assoc_sta_ext_link_metrics.assoc_sta_ext_link_metrics_data[0].last_data_downlink_rate =
        stats->associated_dev3.cli_LastDataDownlinkRate;
    data->assoc_sta_ext_link_metrics.assoc_sta_ext_link_metrics_data[0].last_data_uplink_rate =
        stats->associated_dev3.cli_LastDataUplinkRate;
    data->assoc_sta_ext_link_metrics.assoc_sta_ext_link_metrics_data[0].utilization_receive =
        0; // do we have that data?
    data->assoc_sta_ext_link_metrics.assoc_sta_ext_link_metrics_data[0].utilization_transmit = 0;

    return RETURN_OK;
}
