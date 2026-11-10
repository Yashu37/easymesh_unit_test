/*
 * HANDLER: wifi_hal_connect (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:1155-1208 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It looks the interface up by ap_index,
 * refuses a VAP that is not a STA VAP, stores the requested bss as the interface's backhaul (or, when the bss has an all-zero bssid, the strongest scan-list entry with the VAP's SSID) and
 * calls nl80211_connect_sta().
 *
 * Scaffolding only: get_interface_by_vap_index is a stub over the runner's interfaces; get_vap_ssid (src/wifi_hal_nl80211_utils.c:1557, verbatim); hash_map_get_first / hash_map_get_next are
 * stubs over the runner's scan lists; nl80211_connect_sta records the call and returns the row's result; the *_print macros go to the log sink hwr_print.  Renamed hwr_sg_wifi_hal_connect.
 */
#include "hwr_whc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define wifi_hal_error_print(format, ...)        hwr_print(1, format, ##__VA_ARGS__)
#define get_interface_by_vap_index hwr_whc_get_interface_by_vap_index
#define get_vap_ssid hwr_whc_get_vap_ssid
#define hash_map_get_first hwr_whc_hash_map_get_first
#define hash_map_get_next hwr_whc_hash_map_get_next
#define nl80211_connect_sta hwr_whc_nl80211_connect_sta
#define wifi_hal_connect hwr_sg_wifi_hal_connect

#define NULL_PTR_ASSERT_RC(ptr, retcode) \
    do { \
        if (NULL == ptr) { \
            wifi_hal_error_print("%s:%d NULL pointer!\n", __FUNCTION__, __LINE__); \
            return retcode; \
        } \
    } while (0)
#define NULL_PTR_ASSERT(ptr)            NULL_PTR_ASSERT_RC(ptr, WIFI_HAL_INVALID_ARGUMENTS)

hwr_whc_world_t hwr_whc_world;

extern "C" {
wifi_interface_info_t *get_interface_by_vap_index(unsigned int vap_index)
{
    for (unsigned int i = 0; i < hwr_whc_world.num_ifs; i++)
        if (hwr_whc_world.ifs[i].vap_info.vap_index == vap_index) return &hwr_whc_world.ifs[i];
    return NULL;
}
/* src/wifi_hal_nl80211_utils.c:1557-1560 verbatim */
char *
get_vap_ssid(wifi_vap_info_t *vap)
{
    return (vap->u.sta_info.ignite_enabled) ? vap->u.sta_info.repurposed_ssid : vap->u.sta_info.ssid;
}
void *hash_map_get_first(hash_map_t *map)
{
    if (map == NULL) return NULL;
    map->itr = 0;
    return map->n ? map->items[0] : NULL;
}
void *hash_map_get_next(hash_map_t *map, void *data)
{
    if (map == NULL) return NULL;
    map->itr++;
    return map->itr < map->n ? map->items[map->itr] : NULL;
}
int nl80211_connect_sta(wifi_interface_info_t *interface)
{
    hwr_whc_world.connect_calls++; hwr_whc_world.connect_if = interface;
    return hwr_whc_world.connect_ret;
}

/* --- wifi_hal.c:1155-1208 --- */
INT wifi_hal_connect(INT ap_index, wifi_bss_info_t *bss)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    bssid_t null_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    wifi_bss_info_t *backhaul, *tmp = NULL, *best = NULL;
    int best_rssi = -100;

    NULL_PTR_ASSERT(bss);

    if ((interface = get_interface_by_vap_index(ap_index)) == NULL) {
        wifi_hal_error_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, ap_index);
        return RETURN_ERR;
    }

    vap = &interface->vap_info;
    if (vap->vap_mode != wifi_vap_mode_sta) {
        wifi_hal_error_print("%s:%d:interface for vap index:%d not found\n", __func__, __LINE__, vap->vap_index);
        return WIFI_HAL_INVALID_ARGUMENTS;    // RDKB-45724 - Returns -4 when the ap index is not suitable for station mode
    }

    backhaul = &interface->u.sta.backhaul;

    if ((bss != NULL) && (memcmp(null_mac, bss->bssid, sizeof(bssid_t)) != 0)) {
        memcpy(backhaul, bss, sizeof(wifi_bss_info_t));
    } else {
        // find from scan list
        pthread_mutex_lock(&interface->scan_info_mutex);
        tmp = hash_map_get_first(interface->scan_info_map);
        while (tmp != NULL) {
            if ((strcmp(tmp->ssid, get_vap_ssid(vap)) == 0) &&
                    (tmp->rssi > best_rssi)) {
                best_rssi = tmp->rssi;
                best = tmp;
            }
            tmp = hash_map_get_next(interface->scan_info_map, tmp);
        }

        if (best == NULL) {
            pthread_mutex_unlock(&interface->scan_info_mutex);
            wifi_hal_error_print("%s:%d: Could not find bssid from scan data\n", __func__, __LINE__);
            return RETURN_ERR;
        }

        *backhaul = *best;
        pthread_mutex_unlock(&interface->scan_info_mutex);
    }

    if (nl80211_connect_sta(interface) != 0) {
        return RETURN_ERR;
    }

    return RETURN_OK;
}
}
