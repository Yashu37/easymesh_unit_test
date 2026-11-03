/*
 * HANDLER: instant_msmt_macAddr
 *
 * Copied VERBATIM from OneWifi source/apps/harvester/wifi_harvester.c (no
 * changes). Local array:
 *   - mac_address_t bmac (6 bytes): filled by harvester_str_to_mac_bytes (6-byte copy).
 * strncpy(instantMac, mac_addr, MIN_MAC_LEN=12) into char[32] is bounded.
 * The VAP loop is bounded by getTotalNumberVAPs(). No overrun -> SAFE.
 *
 * Scaffolding (NOT under test): get_wifimgr_obj / getTotalNumberVAPs stubbed;
 * is_harvester_device_associated #define-redirected to a local stub.
 * harvester_str_to_mac_bytes is the real function from its own TU.
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
#ifndef UINT
#define UINT unsigned int
#endif
#define VAP_INDEX(cap, i)   (i)
#define RADIO_INDEX(cap, i) (0)

void harvester_str_to_mac_bytes(char *key, mac_addr_t bmac);

static wifi_mgr_t *get_wifimgr_obj(void) { return (wifi_mgr_t *)iam_mgr_buf; }
static unsigned int getTotalNumberVAPs(void) { return (unsigned int)iam_num_vaps; }
static bool iam_is_assoc(int vap_index, unsigned char *sta) { (void)sta; iam_assoc_checks++; return (vap_index == iam_found_vap); }
#define is_harvester_device_associated(v, s)  iam_is_assoc((v), (unsigned char *)(s))

/* ================= VERBATIM from wifi_harvester.c ================= */
void instant_msmt_macAddr(char *mac_addr)
{
    mac_address_t bmac;
    int i;
    wifi_mgr_t *mgr = get_wifimgr_obj();

    wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: get new client %s stats\n", __func__, __LINE__, mac_addr);
    strncpy(g_harvester_module.instantMac, mac_addr, MIN_MAC_LEN);

    harvester_str_to_mac_bytes(mac_addr, bmac);
    for (i = 0; i < (int)getTotalNumberVAPs(); i++) {
        UINT vap_index = VAP_INDEX(mgr->hal_cap, i);
        UINT radio = RADIO_INDEX(mgr->hal_cap, i);
        if (mgr->hal_cap.wifi_prop.radio_presence[radio] == false) {
            continue;
        }

        if (is_harvester_device_associated(vap_index, bmac)  == true) {
            wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: found client %s on ap %d\n", __func__, __LINE__, mac_addr, vap_index);
            pthread_mutex_lock(&g_harvester_module.queue_lock);
            g_harvester_module.inst_msmt.ap_index = vap_index;
            memcpy(g_harvester_module.inst_msmt.sta_mac, bmac, sizeof(mac_address_t));

            pthread_cond_signal(&g_harvester_module.cond);
            pthread_mutex_unlock(&g_harvester_module.queue_lock);

            break;
        }
    }
}
