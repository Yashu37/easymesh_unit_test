/*
 * HANDLER: em_prepare_scan_response_data
 *
 * Copied VERBATIM from OneWifi source/apps/em/wifi_em.c (only "static"
 * dropped). Local arrays:
 *   - mac_address_t radio_mac (uchar[6]) : mac_address_from_name -> memcpy to ruid.
 *   - mac_addr_str_t mac_str (char[18])  : bounded to_mac_str (final dbg print).
 *   - char time_str[32]                  : get_formatted_time (~22 chars).
 * All output goes into the caller's scan_response: num_results is guarded by
 * EM_MAX_RESULTS, num_neighbors by EM_MAX_NEIGHBORS, time_stamp/ssid/
 * channel_bandwidth are strncpy'd with their exact destination sizes, and the
 * bssid sscanf writes a fixed 6 bytes. No index can run past an array -> SAFE.
 *
 * Scaffolding (NOT under test): get_wifimgr_obj / mac_address_from_name /
 * get_formatted_time / wifi_freq_to_op_class / to_mac_str are stubbed. The
 * wifi_freq_to_op_class stub treats ap_freq AS the operating class (0 -> skip).
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

/* --- scaffolding stubs --- */
static wifi_mgr_t *get_wifimgr_obj(void) { return (wifi_mgr_t *)epsr_mgr_buf; }
static int mac_address_from_name(const char *name, mac_addr_t mac)
{
    (void)name;
    unsigned char fixed[6] = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45};
    memcpy(mac, fixed, 6);
    return RETURN_OK;
}
static char *get_formatted_time(char *t) { snprintf(t, 32, "251103-12:00:00.000000"); return t; }
static int wifi_freq_to_op_class(unsigned int freq) { return (freq == 0) ? 0 : (int)freq; }
static char *to_mac_str(mac_address_t mac, mac_addr_str_t key)
{
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}

/* ================= VERBATIM from wifi_em.c (static dropped) ================= */
int em_prepare_scan_response_data(wifi_provider_response_t *provider_response,
    channel_scan_response_t *scan_response)
{

    unsigned int scan_count = 0, radio_index;
    mac_address_t radio_mac;
    mac_addr_str_t mac_str;
    wifi_neighbor_ap2_t *wifi_scan_data = NULL;
    radio_interface_mapping_t *radio_iface_map = NULL;
    char time_str[32] = { 0 };
    int dwell_time = provider_response->args.dwell_time;

    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();
    wifi_platform_property_t *wifi_prop = &wifi_mgr->hal_cap.wifi_prop;

    wifi_scan_data = (wifi_neighbor_ap2_t *)provider_response->stat_pointer;
    if (wifi_scan_data == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d: wifi_scan_data is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (provider_response->stat_array_size <= 0) {
        wifi_util_error_print(WIFI_EM, "%s:%d: provider_response is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    radio_index = provider_response->args.radio_index;
    scan_count = provider_response->stat_array_size;
    wifi_util_dbg_print(WIFI_EM, "%s:%d radio_index : %d scan_count : %d\n", __func__, __LINE__,
        radio_index, scan_count);

    for (unsigned int k = 0;
         k < (sizeof(wifi_prop->radio_interface_map) / sizeof(radio_interface_mapping_t)); k++) {
        if (wifi_prop->radio_interface_map[k].radio_index == radio_index) {
            radio_iface_map = &(wifi_prop->radio_interface_map[k]);
            break;
        }
    }
    if (radio_iface_map == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d: Unable to find the interface map entry\n", __func__,
            __LINE__);
        return RETURN_ERR;
    }

    memset(scan_response, 0, sizeof(channel_scan_response_t));

    mac_address_from_name(radio_iface_map->interface_name, radio_mac);
    memcpy(scan_response->ruid, radio_mac, sizeof(mac_address_t));

    get_formatted_time(time_str);

    for (int i = 0; i < scan_count; i++) {
        wifi_neighbor_ap2_t *src = &wifi_scan_data[i];

        int op_class = wifi_freq_to_op_class(src->ap_freq);
        if (op_class <= 0) {
            wifi_util_error_print(WIFI_EM, "%s:%d : Invalid op_class (%d). Skipping scan result.\n",
                __func__, __LINE__, op_class);
            continue;
        }

        if (strcmp(src->ap_SSID, "") == 0) {
            wifi_util_error_print(WIFI_EM, "%s:%d : Empty SSID found. Skipping scan result.\n",
                __func__, __LINE__);
            continue;
        }

        int res_index = -1;
        for (int j = 0; j < scan_response->num_results; j++) {
            if (scan_response->results[j].operating_class == op_class &&
                scan_response->results[j].channel == src->ap_Channel) {
                res_index = j;
                break;
            }
        }

        if (res_index == -1) {
            if (scan_response->num_results >= EM_MAX_RESULTS) {
                wifi_util_error_print(WIFI_EM,
                    "%s:%d : Maximum number of scan results reached. Skipping additional "
                    "results.\n",
                    __func__, __LINE__);
                continue;
            }
            res_index = scan_response->num_results;
            scan_response->results[res_index].operating_class = op_class;
            scan_response->results[res_index].channel = src->ap_Channel;
            scan_response->results[res_index].scan_status = 0;
            strncpy(scan_response->results[res_index].time_stamp, time_str,
                sizeof(scan_response->results[res_index].time_stamp));
            scan_response->results[res_index].utilization = src->ap_ChannelUtilization;
            scan_response->results[res_index].noise = src->ap_Noise;
            scan_response->results[res_index].num_neighbors = 0;
            scan_response->results[res_index].aggregate_scan_duration = 0;
            scan_response->results[res_index].scan_type = 0;
            scan_response->num_results++;
        }
        wifi_util_dbg_print(WIFI_EM, "%s:%d op_class : %d channel : %d\n", __func__, __LINE__,
            op_class, src->ap_Channel);

        channel_scan_result_t *res = &scan_response->results[res_index];
        if (res->num_neighbors < EM_MAX_NEIGHBORS) {
            neighbor_bss_t *neighbor = &res->neighbors[res->num_neighbors];
            sscanf(src->ap_BSSID, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &neighbor->bssid[0],
                &neighbor->bssid[1], &neighbor->bssid[2], &neighbor->bssid[3], &neighbor->bssid[4],
                &neighbor->bssid[5]);
            strncpy(neighbor->ssid, src->ap_SSID, sizeof(ssid_t));
            neighbor->signal_strength = src->ap_SignalStrength;
            strncpy(neighbor->channel_bandwidth, src->ap_OperatingChannelBandwidth,
                EM_MAX_CHANNEL_BW_LEN);
            neighbor->bss_color = EM_BSS_COLOR_DEFAULT;
            neighbor->bss_load_element_present = 0;

            /* Initialize to defaults to avoid stale/uninitialized data */
            neighbor->channel_utilization = 0;
            neighbor->station_count = 0;

            if (src->bss_load_element_present) {
                neighbor->bss_load_element_present = src->bss_load_element_present;
                neighbor->channel_utilization = src->ap_ChannelUtilization;
                neighbor->station_count = src->ap_StaCount;
            }
            res->num_neighbors++;
            wifi_util_dbg_print(WIFI_EM, "bss_color 0x%x ch_util %d bss_element_present %d sta_cnt %d for BSSID: %s SSID: %s\n",
                          neighbor->bss_color, neighbor->channel_utilization, neighbor->bss_load_element_present,
			  neighbor->station_count, src->ap_BSSID, src->ap_SSID);
        } else {
            wifi_util_error_print(WIFI_EM, "%s:%d : Maximum number of neighbors reached.\n",
                __func__, __LINE__);
        }
        res->aggregate_scan_duration = dwell_time;
        res->scan_type = EM_SCAN_TYPE_ACTIVE;
    }
    wifi_util_dbg_print(WIFI_EM, "%s:%d Scan results updated for radio mac : %s\n", __func__,
        __LINE__, to_mac_str(radio_mac, mac_str));

    return RETURN_OK;
}
