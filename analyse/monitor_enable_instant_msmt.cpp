/*
 * HANDLER: monitor_enable_instant_msmt
 *
 * Copied VERBATIM from OneWifi source/apps/harvester/wifi_harvester.c (only
 * "static" dropped). Local array:
 *   - mac_addr_str_t sta (char[18]) : bounded to_sta_key (17-char key + NUL).
 * Used only for debug prints. The VAP loop is bounded by getTotalNumberVAPs().
 * No array can be overrun -> SAFE.
 *
 * Scaffolding (NOT under test): get_wifimgr_obj / getTotalNumberVAPs are
 * stubbed; to_sta_key is a bounded local; is_harvester_device_associated /
 * process_instant_msmt_start / process_instant_msmt_stop are #define-redirected
 * to local stubs (their real symbols live in other TUs). Driven by men_* globals.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "common.h"

#define WIFI_HARVESTER 0
#ifndef wifi_util_dbg_print
#define wifi_util_dbg_print(m, ...)   do {} while (0)
#endif
#define DEFAULT_INSTANT_REPORT_TIME 300
#ifndef UINT
#define UINT unsigned int
#endif
#define VAP_INDEX(cap, i)   (i)
#define RADIO_INDEX(cap, i) (0)

/* --- scaffolding stubs driven by men_* globals --- */
static wifi_mgr_t *get_wifimgr_obj(void) { return (wifi_mgr_t *)men_mgr_buf; }
static unsigned int getTotalNumberVAPs(void) { return (unsigned int)men_num_vaps; }
static inline char *to_sta_key(mac_address_t mac, sta_key_t key)
{
    snprintf(key, STA_KEY_LEN, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}
static bool men_is_assoc(int vap_index, mac_address_t sta) { (void)sta; men_assoc_checks++; return (vap_index == men_found_vap); }
#define is_harvester_device_associated(v, s)  men_is_assoc((v), (s))
static void men_start(void) { men_start_calls++; }
#define process_instant_msmt_start()  men_start()
static void men_stop(void) { men_stop_calls++; }
#define process_instant_msmt_stop()  men_stop()

/* ================= VERBATIM from wifi_harvester.c (static dropped) ================= */
void monitor_enable_instant_msmt(mac_address_t sta_mac, bool enable)
{
    mac_addr_str_t sta;
    unsigned int i;
    wifi_mgr_t *mgr = get_wifimgr_obj();

    to_sta_key(sta_mac, sta);
    wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: instant measurements %s for sta:%s\n", __func__, __LINE__, (enable == true)?"start":"stop", sta);

    g_harvester_module.instntMsmtenable = enable;
    pthread_mutex_lock(&g_harvester_module.queue_lock);

    if (g_harvester_module.inst_msmt.active == true) {
        if (enable == false) {
            if (memcmp(g_harvester_module.inst_msmt.sta_mac, sta_mac, sizeof(mac_address_t)) == 0) {
                wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: instant measurements active for sta:%s, should stop\n", __func__, __LINE__, sta);
                g_harvester_module.instantDefOverrideTTL = DEFAULT_INSTANT_REPORT_TIME;
                pthread_mutex_unlock(&g_harvester_module.queue_lock);
                process_instant_msmt_stop();
                return;
            }
        } else {
            wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: instant measurements active for sta:%s, should just return\n", __func__, __LINE__, sta);
        }
        pthread_mutex_unlock(&g_harvester_module.queue_lock);
        return;
    }

    wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: instant measurements not active should look for sta:%s\n", __func__, __LINE__, sta);

    for (i = 0; i < getTotalNumberVAPs(); i++) {
        UINT vap_index = VAP_INDEX(mgr->hal_cap, i);
        UINT radio = RADIO_INDEX(mgr->hal_cap, i);
        if (mgr->hal_cap.wifi_prop.radio_presence[radio] == false) {
            continue;
        }
        if (is_harvester_device_associated(vap_index, sta_mac) == true ) {
            wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: found sta:%s on ap index:%d starting instant measurements\n", __func__, __LINE__, sta, vap_index);
            pthread_mutex_unlock(&g_harvester_module.queue_lock);
            process_instant_msmt_start();
            return;
        }
    }
    pthread_mutex_unlock(&g_harvester_module.queue_lock);
}
