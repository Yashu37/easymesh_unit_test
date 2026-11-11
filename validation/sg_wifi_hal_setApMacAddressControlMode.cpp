/*
 * HANDLER: wifi_hal_setApMacAddressControlMode (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:4922-4966 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It looks the interface up by vap index (RETURN_ERR when there is
 * none), requires the bss to be enabled and the vap to be in AP mode (RETURN_ERR otherwise), maps mac_filter_mode 0 / 1 / 2 to filter disabled / white list / black list in vap_info and returns the result of
 * nl80211_set_acl(interface); any other mode -> RETURN_ERR.
 *
 * Scaffolding only: get_interface_by_vap_index is a lookup over the runner's interfaces; nl80211_set_acl is a recording stub; the print macros go to the log sink hwr_print; renamed
 * hwr_sg_wifi_hal_setApMacAddressControlMode.
 */
#include "hwr_wam.h"
#include <stdio.h>
#include <string.h>

hwr_wam_world_t hwr_wam_world;
#define wifi_hal_error_print(format, ...) hwr_print(1, format, ##__VA_ARGS__)
#define wifi_hal_setApMacAddressControlMode hwr_sg_wifi_hal_setApMacAddressControlMode
static wifi_interface_info_t *get_interface_by_vap_index(unsigned int vap_index)
{
	for (int i = 0; i < HWR_WAM_MAXI; i++) if ((unsigned int)hwr_wam_world.vap_ids[i] == vap_index) return &hwr_wam_world.ifs[i];
	return NULL;
}
static int nl80211_set_acl(wifi_interface_info_t *interface)
{
	hwr_wam_world_t *w = &hwr_wam_world;
	w->acl_calls++; w->acl_if = interface;
	w->acl_enable = interface->vap_info.u.bss_info.mac_filter_enable; w->acl_mode = (int)interface->vap_info.u.bss_info.mac_filter_mode;
	return w->acl_ret;
}

/* --- wifi_hal.c:4922-4966 --- */
int wifi_hal_setApMacAddressControlMode(uint32_t apIndex, uint32_t mac_filter_mode)
{
    wifi_interface_info_t *interface = get_interface_by_vap_index(apIndex);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: WiFi interface not found for vap:%d\n", __func__, __LINE__,
            apIndex);
        return RETURN_ERR;
    }

    wifi_vap_info_t *vap;
    vap = &interface->vap_info;
    if (vap == NULL) {
        wifi_hal_error_print("%s:%d: WiFi interface not found for vap:%d\n", __func__, __LINE__,
            apIndex);
        return RETURN_ERR;
    }

    if (vap->u.bss_info.enabled != true || vap->vap_mode != wifi_vap_mode_ap) {
        wifi_hal_error_print(":%s:%d bss not enabled:%d for vap:%d\n", __func__, __LINE__,
            vap->u.bss_info.enabled, vap->vap_index);
        return RETURN_ERR;
    }

    switch (mac_filter_mode) {
    case 2:
        vap->u.bss_info.mac_filter_enable = true;
        vap->u.bss_info.mac_filter_mode = wifi_mac_filter_mode_black_list;
        break;

    case 1:
        vap->u.bss_info.mac_filter_enable = true;
        vap->u.bss_info.mac_filter_mode = wifi_mac_filter_mode_white_list;
        break;

    case 0:
        vap->u.bss_info.mac_filter_enable = false;
        break;

    default:
        wifi_hal_error_print(":%s:%d Wrong Mac mode %d\n", __func__, __LINE__, mac_filter_mode);
        return RETURN_ERR;
    }

    return (nl80211_set_acl(interface));
}
