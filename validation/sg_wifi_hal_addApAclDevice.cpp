/*
 * HANDLER: wifi_hal_addApAclDevice (src/wifi_hal.c, WIFI_HAL_VERSION_3_PHASE2)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:2090-2150 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It looks the interface up by vap index, formats the MAC
 * with to_mac_str() (no NULL check of DeviceMacAddress), requires an AP VAP, creates interface->acl_map when it is NULL, returns OK when the MAC is already in the map, otherwise mallocs an acl_map_t (result
 * not checked), copies the MAC into it, puts it into the map, calls nl80211_set_acl() and, when the VAP's MAC filter is enabled in black-list mode, nl80211_kick_device(); a failing kick is logged with
 * "%s" of DeviceMacAddress (a 6-byte mac_address_t, not a string).
 *
 * Scaffolding only: get_interface_by_vap_index / hash_map_create / hash_map_get / hash_map_put / nl80211_set_acl / nl80211_kick_device are stubs over the runner's world; to_mac_str is the real code of
 * src/wifi_hal_rdk_util.c; malloc is counted and can be made to fail; the *_print macros go to the log sink hwr_print.  Renamed hwr_sg_wifi_hal_addApAclDevice.
 */
#include "hwr_waa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define wifi_hal_info_print(format, ...)         hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)        hwr_print(1, format, ##__VA_ARGS__)
#define to_mac_str hwr_waa_to_mac_str
#define get_interface_by_vap_index hwr_waa_get_interface_by_vap_index
#define hash_map_create hwr_waa_hash_map_create
#define hash_map_get hwr_waa_hash_map_get
#define hash_map_put hwr_waa_hash_map_put
#define nl80211_set_acl hwr_waa_nl80211_set_acl
#define nl80211_kick_device hwr_waa_nl80211_kick_device
#define wifi_hal_addApAclDevice hwr_sg_wifi_hal_addApAclDevice

hwr_waa_world_t hwr_waa_world;

extern "C" {
/* src/wifi_hal_rdk_util.c:73-78 */
char *to_mac_str (const mac_address_t mac, mac_addr_str_t key) {
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return (char *)key;
}
wifi_interface_info_t *get_interface_by_vap_index(unsigned int vap_index)
{
    for (int k = 0; k < hwr_waa_world.n_if; k++)
        if (hwr_waa_world.ifs[k].vap_info.vap_index == vap_index) return &hwr_waa_world.ifs[k];
    return NULL;
}
hash_map_t *hash_map_create(void)
{
    hwr_waa_world.create_calls++;
    if (hwr_waa_world.create_fail) return NULL;
    memset(&hwr_waa_world.created, 0, sizeof(hwr_waa_world.created));
    return &hwr_waa_world.created;
}
void *hash_map_get(hash_map_t *map, const char *key)
{
    for (int i = 0; i < map->n; i++) if (strcmp(map->keys[i], key) == 0) return map->data[i];
    return NULL;
}
int8_t hash_map_put(hash_map_t *map, char *key, void *data)
{
    hwr_waa_world.put_calls++;
    map->keys[map->n] = key; map->data[map->n] = data; map->n++;
    return 0;
}
int nl80211_set_acl(wifi_interface_info_t *interface) { hwr_waa_world.set_acl_calls++; return hwr_waa_world.set_acl_ret; }
int nl80211_kick_device(wifi_interface_info_t *interface, mac_address_t addr) { hwr_waa_world.kick_calls++; return hwr_waa_world.kick_ret; }
void *hwr_waa_malloc(size_t n)
{
    if (hwr_waa_world.malloc_fail) return NULL;
    return (malloc)(n);
}

#define malloc hwr_waa_malloc
/* --- wifi_hal.c:2090-2150 --- */
INT wifi_hal_addApAclDevice(INT apIndex, mac_address_t DeviceMacAddress)
{
    wifi_interface_info_t *interface = NULL;
    wifi_vap_info_t *vap;
    acl_map_t *acl_map = NULL;
    mac_addr_str_t sta_mac_str;
    char *key = NULL;

    interface = get_interface_by_vap_index(apIndex);
    if(!interface){
        wifi_hal_error_print("%s:%d:interface for vap index:%d not found\n", __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
    vap = &interface->vap_info;

    key = to_mac_str(DeviceMacAddress, sta_mac_str);
    
    wifi_hal_info_print("%s:%d: Interface: %s MAC: %s\n", __func__, __LINE__, interface->name, key);

    if (vap->vap_mode != wifi_vap_mode_ap) {
        wifi_hal_error_print("%s:%d: Not possible to add MAC ACL for STA device\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (interface->acl_map == NULL) {
        wifi_hal_error_print("%s:%d: ACL map is NULL for ap index %d\n", __func__, __LINE__, apIndex);
        interface->acl_map = hash_map_create();
        if (interface->acl_map == NULL) {
            wifi_hal_error_print("%s:%d: ACL map create failure for ap index %d\n", __func__, __LINE__, apIndex);
            return RETURN_ERR;
        }
    }

    acl_map = hash_map_get(interface->acl_map, key);

    if (acl_map != NULL) {
        wifi_hal_error_print("%s:%d: MAC %s already present in acl list\n", __func__, __LINE__, key);
        return RETURN_OK;
    }

    acl_map = (acl_map_t *)malloc(sizeof(acl_map_t));

    memcpy(acl_map->mac_addr_str, key, sizeof(mac_addr_str_t));
    memcpy(acl_map->mac_addr, DeviceMacAddress, sizeof(mac_address_t));

    hash_map_put(interface->acl_map, strdup(key), acl_map);

    if (nl80211_set_acl(interface) != 0) {
        wifi_hal_error_print("%s:%d: MAC %s nl80211_set_acl failure for ap_index:%d\n", __func__, __LINE__, key, apIndex);
        return RETURN_ERR;
    }

    if ((vap->u.bss_info.mac_filter_enable == true) &&
        (vap->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_black_list)) {
        if (nl80211_kick_device(interface, DeviceMacAddress) != 0) {
            wifi_hal_error_print("%s:%d: Unable to kick MAC %s on ap_index %d\n", __func__,
                __LINE__, DeviceMacAddress, apIndex);
        }
    }
    return 0;
}
}
