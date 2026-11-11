/*
 * HANDLER: wifi_hal_configNeighborReports (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:4122-4160 (~/Desktop/G/rdk-wifi-hal), generic build (no CMXB7_PORT, no CONFIG_USE_HOSTAP_BTM_PATCH).  This file holds the ORIGINAL code (no fixes).
 * It finds the AP interface of the VAP, stores enable in the VAP info (nbrReportActivated, bssTransitionActivated) and, under g_wifi_hal.hapd_lock, in conf->bss_transition, sets / clears the neighbour report
 * bit of conf->radio_measurements[0] and stores auto_resp in interface->wnm_bss_trans_query_auto_resp.
 *
 * Scaffolding only: get_interface_by_vap_index is a stub over the runner's world; g_wifi_hal is the stand-in hwr_wcn_world.hal; the *_print macros go to the log sink hwr_print.
 * Renamed hwr_sg_wifi_hal_configNeighborReports.
 */
#include "hwr_wcn.h"
#include <stdio.h>
#include <string.h>

hwr_wcn_world_t hwr_wcn_world;
#define wifi_hal_error_print(format, ...)        hwr_print(1, format, ##__VA_ARGS__)
#define g_wifi_hal hwr_wcn_world.hal
#define get_interface_by_vap_index hwr_wcn_get_interface_by_vap_index
#define wifi_hal_configNeighborReports hwr_sg_wifi_hal_configNeighborReports

extern "C" {
wifi_interface_info_t *get_interface_by_vap_index(unsigned int vap_index)
{
    return vap_index < HWR_WCN_MAXI ? &hwr_wcn_world.ifs[vap_index] : NULL;
}

/* --- wifi_hal.c:4122-4160 --- */
INT wifi_hal_configNeighborReports(UINT apIndex, bool enable, bool auto_resp)
{
    struct hostapd_bss_config *conf;
    wifi_interface_info_t *interface = get_interface_by_vap_index(apIndex);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: [BTM] Cannot find interface with index %u\n", __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

    if (interface->vap_info.vap_mode != wifi_vap_mode_ap) {
        wifi_hal_error_print("%s:%d: [BTM] interface with ap index:%u not in AP mode\n", __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

    interface->vap_info.u.bss_info.nbrReportActivated = enable;
    interface->vap_info.u.bss_info.bssTransitionActivated = enable;

    // - protect interface->u.ap.conf with mutex
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    conf = &interface->u.ap.conf;
    conf->bss_transition = enable;
    if (enable) {
        conf->radio_measurements[0] |= WLAN_RRM_CAPS_NEIGHBOR_REPORT;
#ifdef CMXB7_PORT
        conf->radio_measurements[0] |= WLAN_RRM_CAPS_LINK_MEASUREMENT;
#endif
    }
    else {
         conf->radio_measurements[0] &= ~(WLAN_RRM_CAPS_NEIGHBOR_REPORT);
    }

#ifdef CONFIG_USE_HOSTAP_BTM_PATCH
    conf->wnm_bss_trans_query_auto_resp = auto_resp;
#else
    interface->wnm_bss_trans_query_auto_resp = auto_resp;
#endif
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    return RETURN_OK;
}
}
