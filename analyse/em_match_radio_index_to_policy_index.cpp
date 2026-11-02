/*
 * HANDLER: em_match_radio_index_to_policy_index
 *
 * Copied VERBATIM from OneWifi source/apps/em/wifi_em.c (only "static"
 * dropped). Local array:
 *   - mac_addr_t radio_mac (unsigned char[6]) : filled by
 *     mac_address_from_name() and passed to em_get_radio_index_from_mac().
 * It is a fixed-size internal stack array (ASan stack redzones guard it). The
 * first loop is bounded by the 8-entry radio_interface_map; the second by
 * radio_count. No index can run past an array -> SAFE.
 *
 * Scaffolding (NOT under test): get_wifimgr_obj / mac_address_from_name are
 * stubbed; em_get_radio_index_from_mac is #define-redirected to a local stub
 * (emm_grifm) so this TU does NOT redefine the real symbol from
 * em_get_radio_index_from_mac.cpp. All driven by the emm_* globals.
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
#define wifi_util_error_print(m, ...) do {} while (0)
#endif

/* --- scaffolding stubs driven by emm_* globals (defined in constructor) --- */
static wifi_mgr_t *get_wifimgr_obj(void) { return (wifi_mgr_t *)emm_mgr_buf; }
static int mac_address_from_name(const char *name, mac_addr_t mac)
{
    (void)name;
    unsigned char fixed[6] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35};
    memcpy(mac, fixed, 6);
    return RETURN_OK;
}
/* local stand-in for the real em_get_radio_index_from_mac (lives in its own TU) */
static int emm_grifm(mac_addr_t mac) { (void)mac; emm_grifm_calls++; return emm_found_index; }
#define em_get_radio_index_from_mac(m)  emm_grifm(m)

/* ================= VERBATIM from wifi_em.c (static dropped) ================= */
int em_match_radio_index_to_policy_index(radio_metrics_policies_t *radio_metrics_policies,
    int radio_index)
{
    int radio_count = radio_metrics_policies->radio_count;
    int found_index;
    mac_addr_t radio_mac;
    radio_interface_mapping_t *radio_iface_map = NULL;
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();
    wifi_platform_property_t *wifi_prop = &wifi_mgr->hal_cap.wifi_prop;
    unsigned int i = 0, k = 0;
    (void)i;

    // Testing the code for RCPI-based link metrics is required.
    // Will reassess this block during that process.
    /* for (int i = 0; i < radio_count; i++) {
        found_index = em_get_radio_index_from_mac(
            radio_metrics_policies->radio_metrics_policy[i].ruid);
        if (found_index == radio_index)
            return i;
    } */
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
    for (int i = 0; i < radio_count; i++) {
        found_index = em_get_radio_index_from_mac(radio_mac);
        if (found_index == radio_index)
            return i;
    }

    wifi_util_error_print(WIFI_EM, "%s:%d Radio Index was not matched with policy\n", __func__,
        __LINE__);

    return RETURN_ERR;
}
