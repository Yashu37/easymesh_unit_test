/*
 * HANDLER: wifi_hal_kickAssociatedDevice (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:1784-1841 (~/Desktop/G/rdk-wifi-hal), compiled without BANANA_PI_PORT / KERNEL_6_6 (the plain wifi_drv_sta_disassoc call).  This file holds the
 * ORIGINAL code (no fixes).  It looks the interface up by ap_index, reads the hostapd own_addr and station list from interface->u.ap.hapd under the hapd lock, and disassociates every station of the list
 * when mac is the broadcast address, otherwise just mac, with wifi_drv_sta_disassoc(interface, own_addr, addr, WLAN_REASON_UNSPECIFIED).  mac is dereferenced by memcmp without a NULL check and the
 * interface is read through the AP member of its union whatever its mode (a STA VAP holds wpa_supplicant data there).
 *
 * Scaffolding only: get_interface_by_vap_index (the real search over the interfaces) and wifi_drv_sta_disassoc (src/wifi_hal_nl80211.c) are stubs that look up / record the call; g_wifi_hal is a stand-in
 * with the hapd lock.  The *_print macros go to the log sink hwr_print.  Renamed hwr_sg_wifi_hal_kickAssociatedDevice.
 */
#include "hwr_wka.h"
#include <stdio.h>
#include <string.h>

typedef unsigned char mac_address_t[6];
#define INT int
#define wifi_hal_info_print(format, ...)         hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)        hwr_print(1, format, ##__VA_ARGS__)
#define g_wifi_hal hwr_wka_world.hal
#define get_interface_by_vap_index hwr_wka_get_interface_by_vap_index
#define wifi_drv_sta_disassoc hwr_wka_drv_sta_disassoc
#define wifi_hal_kickAssociatedDevice hwr_sg_wifi_hal_kickAssociatedDevice

hwr_wka_world_t hwr_wka_world;

extern "C" {
wifi_interface_info_t *get_interface_by_vap_index(unsigned int vap_index)
{
    for (unsigned int i = 0; i < g_wifi_hal.num_ifs; i++)
        if (hwr_wka_world.ifs[i].vap_info.vap_index == vap_index) return &hwr_wka_world.ifs[i];
    return NULL;
}
int wifi_drv_sta_disassoc(wifi_interface_info_t *interface, const u8 *own_addr, const u8 *addr, int reason)
{
    if (hwr_wka_world.ncalls < HWR_WKA_MAXC) {
        hwr_wka_call_t *c = &hwr_wka_world.calls[hwr_wka_world.ncalls];
        c->intf = interface; memcpy(c->own, own_addr, ETH_ALEN); memcpy(c->addr, addr, ETH_ALEN); c->reason = reason;
    }
    hwr_wka_world.ncalls++;
    return 0;
}

/* --- wifi_hal.c:1784-1841 --- */
INT wifi_hal_kickAssociatedDevice(INT ap_index, mac_address_t mac)
{
    wifi_interface_info_t *interface;

    interface  = get_interface_by_vap_index(ap_index);
    if (interface ==  NULL) {
        wifi_hal_error_print("%s:%d: NULL Interface pointer \n", __func__, __LINE__);
        return RETURN_ERR;
    }
    u8 own_addr[ETH_ALEN];
    mac_address_t bcastmac= {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    struct hostapd_data *hapd = &interface->u.ap.hapd;
    if(hapd == NULL) {
        wifi_hal_error_print("%s:%d: NULL hapd pointer \n", __func__, __LINE__);
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
        return RETURN_ERR;
    }
    if(hapd->sta_list == NULL) {
        wifi_hal_error_print("%s:%d: hapd->sta_list is NULL \n", __func__, __LINE__);
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
        return RETURN_ERR;
    }
    struct sta_info *tmp = NULL;
    memcpy(own_addr, hapd->own_addr, ETH_ALEN);
    if (memcmp(mac, bcastmac, sizeof(mac_address_t)) == 0) {
        tmp = hapd->sta_list;
        while(tmp) {
#if defined(BANANA_PI_PORT) && defined(KERNEL_6_6)
#if HOSTAPD_VERSION >= 211 && defined(CONFIG_GENERIC_MLO)
            int link_id = wifi_hal_get_mld_link_id(interface);
#else
            int link_id = NL80211_DRV_LINK_ID_NA;
#endif // HOSTAPD_VERSION >= 211 && CONFIG_GENERIC_MLO
            wifi_drv_sta_disassoc(interface, own_addr, tmp->addr, WLAN_REASON_UNSPECIFIED, link_id);
#else
            wifi_drv_sta_disassoc(interface, own_addr, tmp->addr, WLAN_REASON_UNSPECIFIED);
#endif // BANANA_PI_PORT && KERNEL_6_6
            tmp=tmp->next;
        }
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    }
    else {
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
        wifi_hal_info_print("%s:%d:mac is not a broadcast mac address\n", __func__, __LINE__);
#if defined(BANANA_PI_PORT) && defined(KERNEL_6_6)
#if HOSTAPD_VERSION >= 211 && defined(CONFIG_GENERIC_MLO)
        int link_id = wifi_hal_get_mld_link_id(interface);
#else
        int link_id = NL80211_DRV_LINK_ID_NA;
#endif // HOSTAPD_VERSION >= 211 && CONFIG_GENERIC_MLO
        wifi_drv_sta_disassoc(interface, own_addr, mac, WLAN_REASON_UNSPECIFIED, link_id);
#else
        wifi_drv_sta_disassoc(interface, own_addr, mac, WLAN_REASON_UNSPECIFIED);
#endif // BANANA_PI_PORT && KERNEL_6_6
    }
    return RETURN_OK;
}
}
