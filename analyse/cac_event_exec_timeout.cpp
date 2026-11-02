/*
 * HANDLER: cac_event_exec_timeout
 *
 * Function copied VERBATIM from OneWifi source/apps/cac/wifi_cac.c. No fixes.
 * Local arrays:
 *   - mac_str (mac_addr_str_t,18) <- strncpy(mac_str, elem->mac_addr, sizeof(mac_str))
 *                                     and to_mac_str(client->sta_mac, mac_str)  (bounded)
 *   - vap_name[32]  <- convert_vap_index_to_name(...)           (bounded by the stub)
 *   - basic_buf[32] <- snprintf(basic_buf, sizeof(basic_buf),...) (bounded)
 *
 * This harness drives the assoc_map loop (exercises mac_str via strncpy /
 * hash_map_remove) with sta_map = NULL, so the large second loop is compiled
 * but not executed. mac_str is redirected into a runner slot (18) the runner
 * poisons past 18; the caller's elem->mac_addr source is poisoned too.
 *
 * Scaffolding (NOT the function under test): the cac structs, the two
 * control structs, and all ~18 helpers are file-local stubs; hash_map_* run
 * over a tiny runner table.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include "common.h"

/* --- scaffolding --- */
#define WIFI_APPS 0
#define RETURN_OK 0
#define EXP_WEIGHT 0.6
#define WLAN_STATUS_DENIED_POOR_CHANNEL_CONDITIONS 34
typedef enum { status_ok, status_deny } cac_status_t;

typedef struct { char rssi_up_threshold[129]; char snr_threshold[129]; char cu_threshold[129]; char sampling_count[129]; char sampling_interval[129]; } wifi_postassoc_control_t;
typedef struct { char minimum_advertised_mcs[129]; char basic_data_transmit_rates[129]; } wifi_preassoc_control_t;
typedef struct { int radio_NoiseFloor; } wifi_radioTrafficStats2_t;

static void cet_print(int m, const char *f, ...) { char sc[512]; va_list ap; (void)m; va_start(ap,f); vsnprintf(sc,sizeof(sc),f,ap); va_end(ap); }
#define wifi_util_dbg_print   cet_print
#define wifi_util_info_print  cet_print

static wifi_mgr_t *get_wifimgr_obj(void) { return (wifi_mgr_t *)cet_mgr_buf; }
static void *cet_hm_first(void *m) { (void)m; return cet_first; }
static void *cet_hm_next(void *m, void *e) { (void)m; (void)e; return NULL; }   /* single element */
static void *cet_hm_remove(void *m, const char *k) { (void)m; snprintf(cet_removed_key, sizeof(cet_removed_key), "%s", k); cet_remove_calls++; return malloc(sizeof(cac_sta_info_t)); }  /* malloc'd so the handler's free() is valid */
#define hash_map_get_first(m)   cet_hm_first((m))
#define hash_map_get_next(m,e)  cet_hm_next((m),(e))
#define hash_map_remove(m,k)    cet_hm_remove((m),(k))
static void convert_vap_index_to_name(void *prop, unsigned int idx, char *name) { (void)prop; snprintf(name, 32, "vap%u", idx); }
static void wifidb_get_postassoc_ctrl_config(char *v, wifi_postassoc_control_t *c) { (void)v; snprintf(c->rssi_up_threshold,129,"disabled"); snprintf(c->snr_threshold,129,"disabled"); snprintf(c->cu_threshold,129,"disabled"); snprintf(c->sampling_count,129,"5"); snprintf(c->sampling_interval,129,"1"); }
static void wifidb_get_preassoc_ctrl_config(char *v, wifi_preassoc_control_t *c) { (void)v; snprintf(c->minimum_advertised_mcs,129,"disabled"); snprintf(c->basic_data_transmit_rates,129,"disabled"); }
static int  convert_vap_name_to_radio_array_index(void *prop, char *name) { (void)prop; (void)name; return 0; }
static void get_radio_channel_utilization(int ri, int *cu) { (void)ri; *cu = 10; }
static void convert_string_to_int(int **out, char *s) { (void)out; (void)s; }
static char *to_mac_str(mac_address_t mac, mac_addr_str_t key) { snprintf(key,18,"%02x:%02x:%02x:%02x:%02x:%02x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]); return (char*)key; }
static void get_sta_stats_info(void *a) { (void)a; }
static unsigned int getMaxNumberVAPsPerRadio(unsigned int r) { (void)r; return 0; }
static unsigned int getNumberRadios(void) { return 0; }
static void get_radio_data(int ri, wifi_radioTrafficStats2_t *s) { (void)ri; s->radio_NoiseFloor = -90; }
static int  get_min_rate(int *rates, float *out) { (void)rates; if(out)*out=0; return 0; }
static int  get_minrate_from_mcs(char *a, char *b, int c) { (void)a;(void)b;(void)c; return 0; }
static void notify_force_disassociation(void *ctrl, unsigned int ap, const char *r, char *m, int t, int v) { (void)ctrl;(void)ap;(void)r;(void)m;(void)t;(void)v; }
static void wifi_hal_disassoc(unsigned int ap, int reason, mac_address_t mac) { (void)ap;(void)reason;(void)mac; }
static void telemetry_event_cac(const char *a, int i, const char *b, char *c, int d, int e) { (void)a;(void)i;(void)b;(void)c;(void)d;(void)e; }
static void cac_print(const char *f, ...) { (void)f; }

/* redirect: mac_str writes into a runner slot of the same size (18) */
static char *cet_to_mac_str(mac_address_t mac, char *key) { memset(cet_slot_mac,0,CET_MAC_SZ); to_mac_str(mac, cet_slot_mac); memcpy(key, cet_slot_mac, CET_MAC_SZ); return key; }
#define to_mac_str(m,k)  cet_to_mac_str((m),(k))

/* --- copied verbatim from source/apps/cac/wifi_cac.c --- */
int cac_event_exec_timeout(wifi_app_t *apps, void *arg)
{
    hash_map_t *assoc_map = apps->data.u.cac.assoc_req_map;
    hash_map_t *sta_map = apps->data.u.cac.sta_map;
    cac_sta_info_t *elem;
    cac_sta_info_t *tmp_elem;
    cac_associated_devices_t *client;
    wifi_postassoc_control_t wifidb_postassoc_conf = { 0 };
    wifi_preassoc_control_t wifidb_preassoc_conf = { 0 };
    int *preassoc_basic_rates={0};
    char basic_buf[32] = {0};
    wifi_radioTrafficStats2_t chan_stats;
    char vap_name[32];
    int radio_index = 0;
    int chan_util = 0;
    cac_status_t status = status_ok;
    assoc_dev_data_t *assoc_dev_data = NULL;
    unsigned int itr, itrj;
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();
    bool found = false;
    char *str;
    int rssi_conf = 0, snr_conf = 0, cu_conf = 0, mcs_conf = 0, min_rate = 0;
    float min_mbr_rate = 0;
    bool rssi_enabled, snr_enabled, chan_util_enabled, mcs_enabled, mbr_enabled;
    bool threshold_breached = false;

    mac_addr_str_t mac_str = { 0 };

    if (assoc_map != NULL) {
        elem = hash_map_get_first(assoc_map);

        while (elem != NULL) {
            elem->seconds_alive--;

            if(elem->seconds_alive == 0) {
                memset(mac_str, 0, sizeof(mac_str));
                strncpy(mac_str, elem->mac_addr, sizeof(mac_str));
                elem = hash_map_get_next(assoc_map, elem);
                tmp_elem = hash_map_remove(assoc_map, mac_str);

                if (tmp_elem != NULL) {
                    free(tmp_elem);
                }
            } else {
                elem = hash_map_get_next(assoc_map, elem);
            }
        }
    }

    if (sta_map != NULL) {
        client = hash_map_get_first(sta_map);

        while (client != NULL) {
            convert_vap_index_to_name(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, client->ap_index, vap_name);
            wifidb_get_postassoc_ctrl_config(vap_name, &wifidb_postassoc_conf);
            wifidb_get_preassoc_ctrl_config(vap_name, &wifidb_preassoc_conf);
            radio_index = convert_vap_name_to_radio_array_index(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, vap_name);
            if (radio_index < 0) {
                client = hash_map_get_next(sta_map, client);
                continue;
            }
            get_radio_channel_utilization(radio_index, &chan_util);

            if (strcmp(wifidb_postassoc_conf.rssi_up_threshold, "disabled") == 0) {
                rssi_enabled = false;
            } else {
                rssi_enabled = true;
                rssi_conf = atoi(wifidb_postassoc_conf.rssi_up_threshold);
            }

            if (strcmp(wifidb_postassoc_conf.snr_threshold, "disabled") == 0) {
                snr_enabled = false;
            } else {
                snr_enabled = true;
                snr_conf = atoi(wifidb_postassoc_conf.snr_threshold);
            }

            if (strcmp(wifidb_postassoc_conf.cu_threshold, "disabled") == 0) {
                chan_util_enabled = false;
            } else {
                chan_util_enabled = true;
                cu_conf = atoi(wifidb_postassoc_conf.cu_threshold);
            }

            if (strcmp(wifidb_preassoc_conf.minimum_advertised_mcs, "disabled") == 0) {
                mcs_enabled = false;
            } else {
                mcs_enabled = true;
                mcs_conf = atoi(wifidb_preassoc_conf.minimum_advertised_mcs);
            }
            if ((strlen (wifidb_preassoc_conf.basic_data_transmit_rates) > 0) && strcmp(wifidb_preassoc_conf.basic_data_transmit_rates, "disabled")) {
                mbr_enabled = true;
                snprintf(basic_buf, sizeof(basic_buf), "%s", wifidb_preassoc_conf.basic_data_transmit_rates);
                convert_string_to_int(&preassoc_basic_rates, basic_buf);
            } else {
                mbr_enabled = false;
            }

            get_min_rate(preassoc_basic_rates, &min_mbr_rate);
            if(preassoc_basic_rates) {
                free(preassoc_basic_rates);
                preassoc_basic_rates = NULL;
            }

            if (!rssi_enabled && !snr_enabled && !chan_util_enabled && !mcs_enabled && !mbr_enabled) {
                client = hash_map_get_next(sta_map, client);
                continue;
            }

            client->sampling_interval--;

            get_radio_data(radio_index, &chan_stats);

            if (client->sampling_interval == 0 && client->sampling_count != 0) {
                for (itr = 0; itr < getNumberRadios(); itr++) {
                    for (itrj = 0; itrj < getMaxNumberVAPsPerRadio(itr); itrj++) {
                        if (mgr->radio_config[itr]
                                .vaps.rdk_vap_array[itrj]
                                .associated_devices_lock == NULL) {
                            continue;
                        }
                        pthread_mutex_lock(mgr->radio_config[itr]
                                .vaps.rdk_vap_array[itrj]
                                .associated_devices_lock);
                        if (mgr->radio_config[itr]
                                    .vaps.rdk_vap_array[itrj]
                                    .associated_devices_map != NULL &&
                            !found) {
                            assoc_dev_data = hash_map_get_first(mgr->radio_config[itr]
                                    .vaps.rdk_vap_array[itrj]
                                    .associated_devices_map);
                            while (assoc_dev_data != NULL) {
                                get_sta_stats_info(assoc_dev_data);
                                if (((unsigned int)assoc_dev_data->ap_index == client->ap_index) &&
                                    (memcmp(client->sta_mac,
                                         assoc_dev_data->dev_stats.cli_MACAddress,
                                         sizeof(mac_address_t)) == 0)) {
                                    found = true;

                                    if (assoc_dev_data != NULL) {
                                        client->rssi_avg = EXP_WEIGHT * client->rssi_avg +
                                            (1 - EXP_WEIGHT) * assoc_dev_data->dev_stats.cli_RSSI;
                                        client->snr_avg = EXP_WEIGHT * client->snr_avg +
                                            (1 - EXP_WEIGHT) *
                                                (assoc_dev_data->dev_stats.cli_RSSI -
                                                    chan_stats.radio_NoiseFloor);
                                        client->uplink_rate_avg = EXP_WEIGHT *
                                                client->uplink_rate_avg +
                                            (1 - EXP_WEIGHT) *
                                                assoc_dev_data->dev_stats.cli_LastDataUplinkRate;
                                        min_rate = get_minrate_from_mcs(
                                            assoc_dev_data->dev_stats.cli_OperatingStandard,
                                            assoc_dev_data->dev_stats.cli_OperatingChannelBandwidth,
                                            mcs_conf);
                                    }
                                    break;
                                }
                                assoc_dev_data = hash_map_get_next(mgr->radio_config[itr]
                                                                       .vaps.rdk_vap_array[itrj]
                                                                       .associated_devices_map,
                                    assoc_dev_data);
                            }
                        }
                        pthread_mutex_unlock(mgr->radio_config[itr]
                                .vaps.rdk_vap_array[itrj]
                                .associated_devices_lock);
                    }
                }

                found = false;

                client->sampling_count--;

                if (client->sampling_count == 0) {

                    threshold_breached = false;

                    memset(mac_str, 0, sizeof(mac_str));
                    str = to_mac_str(client->sta_mac, mac_str);
                    wifi_util_dbg_print(WIFI_APPS,"%s:%d client rssi = %d, rssi threshold = %d mac_str=%s\r\n", __func__, __LINE__,
                                    client->rssi_avg, rssi_conf,mac_str);
                    if (rssi_enabled && (client->rssi_avg < rssi_conf)) {
                        threshold_breached = true;
                        cac_print("%s:%d, POSTASSOC DENY: %d,RSSI,%s,%d,%d\n", __func__, __LINE__, (client->ap_index + 1), str, rssi_conf, client->rssi_avg);
                        status = status_deny;
                        notify_force_disassociation(&((wifi_mgr_t *)get_wifimgr_obj())->ctrl, client->ap_index, "RSSI", str, rssi_conf, client->rssi_avg);
                        telemetry_event_cac("POSTDENY",client->ap_index, "RSSI", str, rssi_conf, client->rssi_avg);
                    }

                    wifi_util_dbg_print(WIFI_APPS,"%s:%d client snr = %d, snr threshold = %d\r\n", __func__, __LINE__,
                                    client->snr_avg, snr_conf);
                    if (!(threshold_breached) && snr_enabled && (client->snr_avg < snr_conf)) {
                        threshold_breached = true;
                        cac_print("%s:%d, POSTASSOC DENY: %d,SNR,%s,%d,%d\n", __func__, __LINE__, (client->ap_index + 1), str, snr_conf, client->snr_avg);
                        status = status_deny;
                        notify_force_disassociation(&((wifi_mgr_t *)get_wifimgr_obj())->ctrl, client->ap_index , "SNR", str, snr_conf, client->snr_avg);
                        telemetry_event_cac("POSTDENY",client->ap_index, "SNR", str, snr_conf, client->snr_avg);
                    }

                    wifi_util_dbg_print(WIFI_APPS,"%s:%d client cu = %d, cu threshold = %d\r\n", __func__, __LINE__,
                                    chan_util, cu_conf);
                    if (!(threshold_breached) && chan_util_enabled && (chan_util > cu_conf)) {
                        threshold_breached = true;
                        cac_print("%s:%d, POSTASSOC DENY: %d,CU,%s,%d,%d\n", __func__, __LINE__, (client->ap_index + 1), str, cu_conf, chan_util);
                        status = status_deny;
                        notify_force_disassociation(&((wifi_mgr_t *)get_wifimgr_obj())->ctrl, client->ap_index, "CU", str, cu_conf, chan_util);
                        telemetry_event_cac("POSTDENY", client->ap_index, "CU", str, cu_conf, chan_util);
                    }

                    wifi_util_info_print(WIFI_APPS,"%s:%d  client avg rate= %d, mcs_conf = %d min_mbr_rate:%.1f min_rate:%d\r\n", __func__, __LINE__,client->uplink_rate_avg,mcs_conf,min_mbr_rate,min_rate);

                    if(!(threshold_breached) && mcs_enabled && min_rate > 0 && (client->uplink_rate_avg < min_rate)) {
                        threshold_breached = true;
                        cac_print("%s:%d, POSTASSOC DENY: %d,MCS,%s,%d,%d\n", __func__, __LINE__, (client->ap_index + 1), str, mcs_conf, client->uplink_rate_avg);
                        status = status_deny;
                        notify_force_disassociation(&((wifi_mgr_t *)get_wifimgr_obj())->ctrl, client->ap_index, "MCS", str, mcs_conf, client->uplink_rate_avg);
                        telemetry_event_cac("POSTDENY",client->ap_index, "MCS", str,mcs_conf, client->uplink_rate_avg);
                    }
                    if(!(threshold_breached) && mbr_enabled && min_mbr_rate > 0 && (client->uplink_rate_avg < min_mbr_rate)) {
                        cac_print("%s:%d, POSTASSOC DENY: %d,MBR,%s,%d,%d\n", __func__, __LINE__, (client->ap_index + 1), str, (int)min_mbr_rate, client->uplink_rate_avg);
                        status = status_deny;
                        notify_force_disassociation(&((wifi_mgr_t *)get_wifimgr_obj())->ctrl, client->ap_index, "MBR", str, (int)min_mbr_rate, client->uplink_rate_avg);
                        telemetry_event_cac("POSTDENY",client->ap_index, "MBR", str, (int)min_mbr_rate, client->uplink_rate_avg);
                    }

                    if (status == status_deny) {
                        wifi_hal_disassoc(client->ap_index, WLAN_STATUS_DENIED_POOR_CHANNEL_CONDITIONS, client->sta_mac);
                    } else {
                        client->sampling_count = atoi(wifidb_postassoc_conf.sampling_count);
                    }
                }
                client->sampling_interval = atoi(wifidb_postassoc_conf.sampling_interval);
            }

            client = hash_map_get_next(sta_map, client);
        }
    }

    return RETURN_OK;
}
