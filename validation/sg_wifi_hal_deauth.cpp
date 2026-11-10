/*
 * HANDLER: wifi_hal_deauth (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:705-718 (~/Desktop/G/rdk-wifi-hal), compiled with HOSTAPD_2_10 defined (the branch that does the work).  This file
 * holds the ORIGINAL code: no fix is applied.  It looks the interface up by vap_index, reads the hostapd own_addr from interface->u.ap.hapd under the hapd lock and calls
 * wifi_drv_sta_deauth(interface, own_addr, mac, status).  The lookup result is not checked (get_interface_by_vap_index returns NULL for an unknown vap_index) and the interface
 * is read through the AP member of its union whatever its mode (a STA VAP holds wpa_supplicant data there).  mac is only forwarded.
 *
 * Scaffolding only: get_interface_by_vap_index (src/wifi_hal_nl80211_utils.c:2312, the real search over the interfaces) and wifi_drv_sta_deauth (src/wifi_hal_nl80211.c) are stubs that
 * look up / record the call; g_wifi_hal is a stand-in with the hapd lock.  Renamed hwr_sg_wifi_hal_deauth.
 */
#include "hwr_wda.h"
#include <string.h>

#define HOSTAPD_2_10 1
#define g_wifi_hal hwr_wda_world.hal
#define get_interface_by_vap_index hwr_wda_get_interface_by_vap_index
#define wifi_drv_sta_deauth hwr_wda_drv_sta_deauth
#define wifi_hal_deauth hwr_sg_wifi_hal_deauth

hwr_wda_world_t hwr_wda_world;

extern "C" {
wifi_interface_info_t *get_interface_by_vap_index(unsigned int vap_index)
{
    for (unsigned int i = 0; i < g_wifi_hal.num_ifs; i++)
        if (hwr_wda_world.ifs[i].vap_info.vap_index == vap_index) return &hwr_wda_world.ifs[i];
    return NULL;
}
int wifi_drv_sta_deauth(wifi_interface_info_t *interface, const u8 *own_addr, const u8 *mac, int status)
{
    hwr_wda_world.deauth_calls++; hwr_wda_world.d_if = interface; memcpy(hwr_wda_world.d_own, own_addr, ETH_ALEN); hwr_wda_world.d_mac = mac; hwr_wda_world.d_status = status;
    return 0;
}

/* --- wifi_hal.c:705-718 --- */
void wifi_hal_deauth(int vap_index, int status, uint8_t *mac)
{
    u8 own_addr[ETH_ALEN];
    wifi_interface_info_t *interface = get_interface_by_vap_index(vap_index);
    struct hostapd_data *hapd = &interface->u.ap.hapd;

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    memcpy(own_addr, hapd->own_addr, ETH_ALEN);
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
#ifdef HOSTAPD_2_10
    wifi_drv_sta_deauth(interface, own_addr, mac, status);
#endif
    return;
}
}
