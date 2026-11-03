/*
 * HANDLER: process_instant_msmt_monitor
 *
 * Copied VERBATIM from OneWifi source/apps/harvester/wifi_harvester.c (only
 * "static" dropped). Local array:
 *   - char s_mac[MIN_MAC_LEN+1] (13) : snprintf(s_mac, MIN_MAC_LEN+1,
 *     "%02x%02x%02x%02x%02x%02x", 6 bytes) = 12 hex chars + NUL, exactly 13.
 * The radio loop is bounded by getNumberRadios() (<= MAX_NUM_RADIOS), the stat
 * loop by stat_array_size. No array can be overrun -> SAFE.
 *
 * Scaffolding (NOT under test): getNumberRadios / get_dev_stats_for_radio are
 * stubbed; process_instant_msmt_stop and upload_single_client_msmt_data are
 * #define-redirected to local stubs (their real symbols live elsewhere).
 * Driven by the pim_* globals + g_harvester_module.
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
#define WIFI_HARVESTER 0
#ifndef wifi_util_dbg_print
#define wifi_util_dbg_print(m, ...)   do {} while (0)
#define wifi_util_error_print(m, ...) do {} while (0)
#endif
#define DEFAULT_INSTANT_REPORT_TIME 300

/* --- scaffolding stubs driven by pim_* globals --- */
static unsigned int getNumberRadios(void) { return (unsigned int)pim_num_radios; }
static int get_dev_stats_for_radio(unsigned int radio_index, radio_data_t *rd) { (void)radio_index; (void)rd; return pim_devstats_fail ? RETURN_ERR : RETURN_OK; }
static void pim_stop(void) { pim_stop_calls++; }
#define process_instant_msmt_stop()  pim_stop()
static void pim_upload(sta_data_t *s) { (void)s; pim_upload_calls++; }
#define upload_single_client_msmt_data(s)  pim_upload((s))

/* ================= VERBATIM from wifi_harvester.c (static dropped) ================= */
void process_instant_msmt_monitor(wifi_provider_response_t *provider_response)
{
    if (g_harvester_module.count >= g_harvester_module.maxCount) {
        wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: instant polling freq reached threshold\n", __func__, __LINE__);
        g_harvester_module.instantDefOverrideTTL = DEFAULT_INSTANT_REPORT_TIME;
        g_harvester_module.instntMsmtenable = false;
        process_instant_msmt_stop();
    } else {
        if (g_harvester_module.count == 0) {
            for (unsigned int radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
                g_harvester_module.radio_data[radio_index] = (radio_data_t *) malloc (sizeof(radio_data_t));
                if (g_harvester_module.radio_data[radio_index] == NULL) {
                    wifi_util_error_print(WIFI_HARVESTER, "%s:%d: Unable to allocate memory \n", __func__, __LINE__);
                    return;
                }
                memset(g_harvester_module.radio_data[radio_index], 0, sizeof(radio_data_t));
                if (get_dev_stats_for_radio(radio_index, (radio_data_t *)g_harvester_module.radio_data[radio_index]) != RETURN_OK) {
                    wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Error getting radio datas\n", __func__, __LINE__);
                    continue;
                }
            }
        }

        g_harvester_module.count += 1;
        wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: client %s on ap %d\n", __func__, __LINE__, g_harvester_module.instantMac, g_harvester_module.inst_msmt.ap_index);
        sta_data_t *assoc_stats = NULL;
        assoc_stats = (sta_data_t *) provider_response->stat_pointer;

        char s_mac[MIN_MAC_LEN+1];

        snprintf(s_mac, MIN_MAC_LEN+1, "%02x%02x%02x%02x%02x%02x", g_harvester_module.inst_msmt.sta_mac[0],
            g_harvester_module.inst_msmt.sta_mac[1],g_harvester_module.inst_msmt.sta_mac[2], g_harvester_module.inst_msmt.sta_mac[3],
            g_harvester_module.inst_msmt.sta_mac[4], g_harvester_module.inst_msmt.sta_mac[5]);

        wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: get single connected client %s stats\n", __func__, __LINE__, s_mac);
        wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: value of stat array size is %u\n", __func__, __LINE__, provider_response->stat_array_size);
        for (unsigned int count = 0; count < provider_response->stat_array_size; count++) {
            if (!memcmp(g_harvester_module.inst_msmt.sta_mac, assoc_stats[count].sta_mac, sizeof(mac_address_t))) {
                wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Found a match for mac address %s \n", __func__, __LINE__, s_mac);
                upload_single_client_msmt_data(&assoc_stats[count]);
                break;
            }
            else {
                wifi_util_dbg_print(WIFI_HARVESTER, "%s: provider_response->sta_mac is %02x:%02x:%02x:%02x:%02x:%02x\n", __func__, assoc_stats[count].sta_mac[0],
                        assoc_stats[count].sta_mac[1], assoc_stats[count].sta_mac[2], assoc_stats[count].sta_mac[3],
                        assoc_stats[count].sta_mac[4], assoc_stats[count].sta_mac[5]);
            }
        }
    }
}
