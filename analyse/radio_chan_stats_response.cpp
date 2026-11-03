/*
 * HANDLER: radio_chan_stats_response
 *
 * Copied VERBATIM from OneWifi source/apps/em/wifi_em.c (only "static"
 * dropped). Local arrays:
 *   - mac_addr_t radio_mac (uchar[6])   : mac_address_from_name -> memcpy to ruid.
 *   - mac_addr_str_t radio_str (char[18]): bounded to_mac_str.
 * radio_index is validated (< MAX_NUM_RADIOS) before any cache index; the
 * per-channel loop is bounded by stat_array_size (the source array's own
 * length) and the per-vap loop by radio->vaps.num_vaps (<= MAX_NUM_VAP_PER_RADIO
 * on well-formed config). No local array can be overrun -> SAFE.
 *
 * Scaffolding (NOT under test): get_wifimgr_obj / find_radio_config_by_index /
 * mac_address_from_name / to_mac_str / em_survey_fraction are stubbed and
 * driven by the rcs_* globals. em_ap_metrics_report_cache / em_chan_survey_prev
 * are the shared globals (defined in the em_client_stats_store / this
 * constructor).
 *
 * NOTE: line "return;" in an int-returning function is kept verbatim (the
 * upstream code; -fpermissive allows it).
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

/* vap entries come from wifi_vap_info_map_t.vap_array (erm_vap_info_t) in common.h */

/* --- scaffolding stubs driven by rcs_* globals --- */
static wifi_mgr_t *get_wifimgr_obj(void) { return (wifi_mgr_t *)rcs_mgr_buf; }
static rdk_wifi_radio_t *find_radio_config_by_index(int radio_index) { (void)radio_index; return rcs_radio_null ? NULL : &rcs_radio; }
static int mac_address_from_name(const char *name, mac_addr_t mac)
{
    (void)name;
    unsigned char fixed[6] = {0x50, 0x51, 0x52, 0x53, 0x54, 0x55};
    memcpy(mac, fixed, 6);
    return RETURN_OK;
}
static char *to_mac_str(mac_address_t mac, mac_addr_str_t key)
{
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}
static unsigned char em_survey_fraction(unsigned long long num, unsigned long long den)
{
    if (den == 0) return 0;
    unsigned long long v = (num * 255ULL) / den;
    return (v > 255ULL) ? 255 : (unsigned char)v;
}

/* ================= VERBATIM from wifi_em.c (static dropped) ================= */
int radio_chan_stats_response(wifi_provider_response_t *provider_response)
{
    int radio_index = -1;
    unsigned int count = 0;
    radio_chan_data_t *channel_stats = NULL;
    radio_interface_mapping_t *radio_iface_map = NULL;
    rdk_wifi_radio_t *radio = NULL;
    wifi_vap_info_map_t *vap_map = NULL;
    ap_metrics_data_t *ap_data = NULL;
    em_cache_ap_metrics_t *ap_metrics = NULL;
    erm_vap_info_t *vap = NULL;
    int j = 0;
    mac_addr_t radio_mac;
    mac_addr_str_t radio_str;
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();
    wifi_platform_property_t *wifi_prop = &wifi_mgr->hal_cap.wifi_prop;
    unsigned int i = 0, k = 0;
    radio_metrics_t *radio_metrics = NULL;
    em_chan_survey_prev_t *survey_prev = NULL;
    unsigned long long d_total = 0, d_tx = 0, d_self = 0, d_rx = 0, d_busy = 0;
    int anpi = 0;
    unsigned char util255 = 0;
    (void)i; (void)ap_metrics;

    radio_index = provider_response->args.radio_index;
    if (radio_index >= MAX_NUM_RADIOS) {
        wifi_util_error_print(WIFI_EM, "%s:%d Invalid radio index %d\n", __func__, __LINE__,
            radio_index);
        return RETURN_ERR;
    }

    if (provider_response->stat_array_size <= 0) {
        wifi_util_error_print(WIFI_EM, "%s:%d: provider_response is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    radio = find_radio_config_by_index(radio_index);
    if (radio == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d: NULL Pointer\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    vap_map = &radio->vaps.vap_map;
    if (vap_map == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d: NULL Pointer\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    channel_stats = (radio_chan_data_t *)provider_response->stat_pointer;

    wifi_util_dbg_print(WIFI_EM, "%s:%d radio_index : %d stats_array_size : %d\r\n", __func__,
        __LINE__, radio_index, provider_response->stat_array_size);

    for (count = 0; count < provider_response->stat_array_size; count++) {
        for (k = 0;
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

        mac_address_from_name(radio_iface_map->interface_name, radio_mac);
        to_mac_str(radio_mac, radio_str);

        radio_metrics = &em_ap_metrics_report_cache.radio_report[radio_index].radio_metrics;
        memcpy(radio_metrics->ruid, radio_mac, sizeof(mac_addr_t));

        survey_prev = &em_chan_survey_prev[radio_index];
        if (survey_prev->total != 0 &&
            survey_prev->chan == channel_stats[count].ch_number &&
            channel_stats[count].ch_utilization_total > survey_prev->total &&
            channel_stats[count].ch_utilization_busy >= survey_prev->busy &&
            channel_stats[count].ch_utilization_busy_tx >= survey_prev->busy_tx &&
            channel_stats[count].ch_utilization_busy_self >= survey_prev->busy_self &&
            channel_stats[count].ch_utilization_busy_rx >= survey_prev->busy_rx) {
            d_total = channel_stats[count].ch_utilization_total - survey_prev->total;
            d_tx = channel_stats[count].ch_utilization_busy_tx - survey_prev->busy_tx;
            d_self = channel_stats[count].ch_utilization_busy_self - survey_prev->busy_self;
            d_rx = channel_stats[count].ch_utilization_busy_rx - survey_prev->busy_rx;
            d_busy = channel_stats[count].ch_utilization_busy - survey_prev->busy;

            radio_metrics->transmit = em_survey_fraction(d_tx, d_total);
            radio_metrics->receive_self = em_survey_fraction(d_self, d_total);
            radio_metrics->receive_other = em_survey_fraction((d_rx > d_self) ? (d_rx - d_self) : 0, d_total);
            util255 = em_survey_fraction((d_busy > d_tx + d_rx) ? d_busy : d_tx + d_rx, d_total);
        } else {
            radio_metrics->transmit = 0;
            radio_metrics->receive_self = 0;
            radio_metrics->receive_other = 0;
            util255 = 0;
        }
        survey_prev->chan = channel_stats[count].ch_number;
        survey_prev->total = channel_stats[count].ch_utilization_total;
        survey_prev->busy = channel_stats[count].ch_utilization_busy;
        survey_prev->busy_tx = channel_stats[count].ch_utilization_busy_tx;
        survey_prev->busy_self = channel_stats[count].ch_utilization_busy_self;
        survey_prev->busy_rx = channel_stats[count].ch_utilization_busy_rx;

        anpi = (channel_stats[count].ch_noise + 110) * 2;
        if (anpi < 0) {
            anpi = 0;
        } else if (anpi > 220) {
            anpi = 220;
        }
        radio_metrics->noise = (unsigned char)anpi;

        // now save radio channel util for each vap
        for (j = 0; j < (int)radio->vaps.num_vaps; j++) {
            vap = &vap_map->vap_array[j];
            if (vap == NULL) {
                wifi_util_dbg_print(WIFI_EM, "%s:%d NULL VAP\r\n", __func__, __LINE__);
                continue;
            }

            if ((em_ap_metrics_report_cache.radio_report[radio_index].ap_data[j].vap_index >= 0) &&
                (memcmp(em_ap_metrics_report_cache.radio_report[radio_index].ap_data[j].ap_metrics.bssid, vap->u.bss_info.bssid,
                     sizeof(mac_addr_t)) != 0)) {
                ap_data = &em_ap_metrics_report_cache.radio_report[radio_index].ap_data[j];
                ap_data->vap_index = vap->vap_index;

                ap_metrics = &ap_data->ap_metrics;
                if (ap_metrics != NULL) {
                    ap_metrics->channel_util = util255;
                }
            } else {
                ap_data = &em_ap_metrics_report_cache.radio_report[radio_index].ap_data[j];
                if (ap_data->vap_index != (int)vap->vap_index){
                    continue;
                }

                ap_metrics = &ap_data->ap_metrics;
                if (ap_metrics != NULL) {
                    ap_metrics->channel_util = util255;
                }
            }
        }
    }

    wifi_util_dbg_print(WIFI_EM, "%s:%d Process of radio chann stats response complete\r\n", __func__,
        __LINE__);

    return RETURN_OK;
}
