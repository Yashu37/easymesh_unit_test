/*
 * HANDLER: wifi_hal_delApAclDevices (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:2321-2363 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It looks the interface up by vap index, requires an AP VAP and
 * a non-NULL acl_map (NULL -> error, an empty map -> OK), then walks the map: for every entry it copies the 18 bytes of acl_map->mac_addr_str into the stack array mac_str, advances the iterator, removes the
 * entry by the key mac_str (hash_map_remove compares with strncmp(.., 100), so mac_str must be a terminated string) and frees it; finally it returns nl80211_set_acl().
 *
 * Scaffolding only: get_interface_by_vap_index / hash_map_get_first / hash_map_get_next / hash_map_remove / nl80211_set_acl are stubs over the runner's world following src/collection.c; the *_print macros
 * go to the log sink hwr_print.  Renamed hwr_sg_wifi_hal_delApAclDevices.
 */
#include "hwr_wdm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define wifi_hal_dbg_print(format, ...)          hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)        hwr_print(1, format, ##__VA_ARGS__)
#define get_interface_by_vap_index hwr_wdm_get_interface_by_vap_index
#define hash_map_get_first hwr_wdm_hash_map_get_first
#define hash_map_get_next hwr_wdm_hash_map_get_next
#define hash_map_remove hwr_wdm_hash_map_remove
#define nl80211_set_acl hwr_wdm_nl80211_set_acl
#define wifi_hal_delApAclDevices hwr_sg_wifi_hal_delApAclDevices

hwr_wdm_world_t hwr_wdm_world;

extern "C" {
wifi_interface_info_t *get_interface_by_vap_index(unsigned int vap_index)
{
    for (int k = 0; k < hwr_wdm_world.n_if; k++)
        if (hwr_wdm_world.ifs[k].vap_info.vap_index == vap_index) return &hwr_wdm_world.ifs[k];
    return NULL;
}
void *hash_map_get_first(hash_map_t *map)
{
    if (map == NULL) return NULL;
    map->itr = -1;
    if (map->n == 0) return NULL;
    map->itr = 0;
    return map->data[0];
}
void *hash_map_get_next(hash_map_t *map, void *data)
{
    if (map == NULL) return NULL;
    if (map->itr >= 0 && map->itr < map->n && map->data[map->itr] == data) {
        map->itr++;
        return map->itr < map->n ? map->data[map->itr] : NULL;
    }
    for (int i = 0; i < map->n; i++) if (map->data[i] == data) { map->itr = i + 1; return map->itr < map->n ? map->data[map->itr] : NULL; }
    return NULL;
}
void *hash_map_remove(hash_map_t *map, const char *key)
{
    hwr_wdm_world.remove_calls++;
    for (int i = 0; i < map->n; i++) if (strncmp(map->keys[i], key, 100) == 0) {
        void *d = map->data[i];
        free(map->keys[i]);
        for (int j = i; j + 1 < map->n; j++) { map->keys[j] = map->keys[j + 1]; map->data[j] = map->data[j + 1]; }
        map->n--;
        if (i < map->itr) map->itr--;                  /* the iterator keeps pointing at the same element */
        return d;
    }
    return NULL;
}
int nl80211_set_acl(wifi_interface_info_t *interface) { hwr_wdm_world.set_acl_calls++; return hwr_wdm_world.set_acl_ret; }

/* --- wifi_hal.c:2321-2363 --- */
INT wifi_hal_delApAclDevices(INT apIndex)
{
    wifi_interface_info_t *interface = NULL;
    wifi_vap_info_t *vap;
    acl_map_t *acl_map, *temp_acl_map;
    mac_addr_str_t mac_str;

    interface = get_interface_by_vap_index(apIndex);
    if(!interface){
        wifi_hal_error_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
    vap = &interface->vap_info;
    wifi_hal_dbg_print("%s:%d: Interface: %s \n", __func__, __LINE__, interface->name);
    
    if (vap->vap_mode != wifi_vap_mode_ap) {
        wifi_hal_dbg_print("%s:%d: Not possible to del MAC ACL for STA device\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (interface->acl_map == NULL) {
        wifi_hal_dbg_print("%s:%d: ACL map is NULL for ap index %d\n", __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

    acl_map = hash_map_get_first(interface->acl_map);

    if (acl_map == NULL) {
        wifi_hal_dbg_print("%s:%d: ACL list is empty for ap index %d\n", __func__, __LINE__, apIndex);
        return RETURN_OK;
    }

    while (acl_map != NULL) {
        memcpy(&mac_str, &acl_map->mac_addr_str, sizeof(mac_addr_str_t));
        acl_map = hash_map_get_next(interface->acl_map, acl_map);
        temp_acl_map = hash_map_remove(interface->acl_map, mac_str);
        if (temp_acl_map != NULL) {
            free(temp_acl_map);
        }
    }

    return nl80211_set_acl(interface);
}
}
