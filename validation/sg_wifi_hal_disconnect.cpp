/*
 * HANDLER: wifi_hal_disconnect (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:1210-1231 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It looks the interface up by ap_index, refuses a
 * VAP that is not a STA VAP (-4) and calls nl80211_disconnect_sta() (-1 on failure).
 *
 * Scaffolding only: get_interface_by_vap_index is a stub over the runner's interfaces; nl80211_disconnect_sta records the call and returns the row's result; the *_print macros go to the log sink
 * hwr_print.  Renamed hwr_sg_wifi_hal_disconnect.
 */
#include "hwr_wdc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define wifi_hal_error_print(format, ...)        hwr_print(1, format, ##__VA_ARGS__)
#define get_interface_by_vap_index hwr_wdc_get_interface_by_vap_index
#define nl80211_disconnect_sta hwr_wdc_nl80211_disconnect_sta
#define wifi_hal_disconnect hwr_sg_wifi_hal_disconnect

hwr_wdc_world_t hwr_wdc_world;

extern "C" {
wifi_interface_info_t *get_interface_by_vap_index(unsigned int vap_index)
{
    for (unsigned int i = 0; i < hwr_wdc_world.num_ifs; i++)
        if (hwr_wdc_world.ifs[i].vap_info.vap_index == vap_index) return &hwr_wdc_world.ifs[i];
    return NULL;
}
int nl80211_disconnect_sta(wifi_interface_info_t *interface)
{
    hwr_wdc_world.disc_calls++; hwr_wdc_world.disc_if = interface;
    return hwr_wdc_world.disc_ret;
}

/* --- wifi_hal.c:1210-1231 --- */
INT wifi_hal_disconnect(INT ap_index)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;

    if ((interface = get_interface_by_vap_index(ap_index)) == NULL) {
        wifi_hal_error_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, ap_index);
        return RETURN_ERR;
    }

    vap = &interface->vap_info;
    if (vap->vap_mode != wifi_vap_mode_sta) {
        wifi_hal_error_print("%s:%d:interface for vap index:%d not found\n", __func__, __LINE__, vap->vap_index);
        return WIFI_HAL_INVALID_ARGUMENTS;     // RDKB-45722 - Returns -4 when the ap index is not suitable for station mode
    }

    if (nl80211_disconnect_sta(interface) != 0) {
        return RETURN_ERR;
    }

    return RETURN_OK;
}
}
