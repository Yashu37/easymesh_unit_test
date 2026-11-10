/*
 * HANDLER: wifi_hal_delApAclDevice (src/wifi_hal.c, CHAR * variant)
 *
 * Function copied from rdk-wifi-hal (verbatim apart from fixes 1-3): src/wifi_hal.c:2269-2318 (~/Desktop/G/rdk-wifi-hal), the variant compiled when WIFI_HAL_VERSION_3_PHASE2 is NOT defined.  The WIFI_HAL_VERSION_3_PHASE2 variant
 * (src/wifi_hal.c:2214-2267) does not compile: it calls to_mac_str(sta_mac, ...) and sta_mac is not declared in that function (the mac_address_t parameter is DeviceMacAddress).  This file holds the ORIGINAL
 * code (no fixes).  It looks the interface up by vap index, requires an AP VAP, returns OK when interface->acl_map is NULL or the MAC string is not a key of the map, otherwise removes the entry, frees it
 * and calls nl80211_set_acl(); when that fails the entry is rebuilt (malloc not checked, 18 bytes copied from DeviceMacAddress, MAC bytes parsed from it) and put back, result -1.
 *
 * Scaffolding only: get_interface_by_vap_index / hash_map_get / hash_map_remove / hash_map_put / nl80211_set_acl are stubs over the runner's world; to_mac_bytes is the real code of
 * src/wifi_hal_rdk_util.c; malloc is counted and can be made to fail; the *_print macros go to the log sink hwr_print.  Renamed hwr_sg_wifi_hal_delApAclDevice.
 */
#include "hwr_wdl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define wifi_hal_info_print(format, ...)         hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)        hwr_print(1, format, ##__VA_ARGS__)
#define to_mac_bytes hwr_wdl_to_mac_bytes
#define get_interface_by_vap_index hwr_wdl_get_interface_by_vap_index
#define hash_map_get hwr_wdl_hash_map_get
#define hash_map_remove hwr_wdl_hash_map_remove
#define hash_map_put hwr_wdl_hash_map_put
#define nl80211_set_acl hwr_wdl_nl80211_set_acl
#define wifi_hal_delApAclDevice hwr_sg_wifi_hal_delApAclDevice

hwr_wdl_world_t hwr_wdl_world;

extern "C" {
/* src/wifi_hal_rdk_util.c:81-88 */
void to_mac_bytes (mac_addr_str_t key, mac_address_t bmac) {
   unsigned int mac[6];
    sscanf(key, "%02x:%02x:%02x:%02x:%02x:%02x",
             &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
   bmac[0] = mac[0]; bmac[1] = mac[1]; bmac[2] = mac[2];
   bmac[3] = mac[3]; bmac[4] = mac[4]; bmac[5] = mac[5];

}
wifi_interface_info_t *get_interface_by_vap_index(unsigned int vap_index)
{
    for (int k = 0; k < hwr_wdl_world.n_if; k++)
        if (hwr_wdl_world.ifs[k].vap_info.vap_index == vap_index) return &hwr_wdl_world.ifs[k];
    return NULL;
}
void *hash_map_get(hash_map_t *map, const char *key)
{
    for (int i = 0; i < map->n; i++) if (strncmp(map->keys[i], key, 100) == 0) return map->data[i];
    return NULL;
}
void *hash_map_remove(hash_map_t *map, const char *key)
{
    hwr_wdl_world.remove_calls++;
    for (int i = 0; i < map->n; i++) if (strncmp(map->keys[i], key, 100) == 0) {
        void *d = map->data[i];
        free(map->keys[i]);
        for (int j = i; j + 1 < map->n; j++) { map->keys[j] = map->keys[j + 1]; map->data[j] = map->data[j + 1]; }
        map->n--;
        return d;
    }
    return NULL;
}
int8_t hash_map_put(hash_map_t *map, char *key, void *data)
{
    hwr_wdl_world.put_calls++;
    map->keys[map->n] = key; map->data[map->n] = data; map->n++;
    return 0;
}
int nl80211_set_acl(wifi_interface_info_t *interface) { hwr_wdl_world.set_acl_calls++; return hwr_wdl_world.set_acl_ret; }
void *hwr_wdl_malloc(size_t n)
{
    if (hwr_wdl_world.malloc_fail) return NULL;
    return (malloc)(n);
}

#define malloc hwr_wdl_malloc
/* --- wifi_hal.c:2269-2318 --- */
INT wifi_hal_delApAclDevice(INT apIndex, CHAR *DeviceMacAddress)
{
    wifi_interface_info_t *interface = NULL;
    wifi_vap_info_t *vap;
    acl_map_t *acl_map = NULL;

    interface = get_interface_by_vap_index(apIndex);
    if(!interface){
        wifi_hal_error_print("%s:%d:interface for vap index:%d not found\n", __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
    /* ---------- start fix 1: a NULL DeviceMacAddress was passed to hash_map_get() (strncmp on NULL). */
    if (DeviceMacAddress == NULL) {
        wifi_hal_error_print("%s:%d: NULL MAC address for ap index %d\n", __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
    /* ---------- end fix 1 */
    vap = &interface->vap_info;
    
    wifi_hal_info_print("%s:%d: Interface: %s MAC: %s\n", __func__, __LINE__, interface->name, DeviceMacAddress);

    if (vap->vap_mode != wifi_vap_mode_ap) {
        wifi_hal_error_print("%s:%d: Not possible to del MAC ACL for STA device\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (interface->acl_map == NULL) {
        wifi_hal_error_print("%s:%d: ACL map is NULL for ap index %d\n", __func__, __LINE__, apIndex);
        return RETURN_OK;
    }

    acl_map = hash_map_get(interface->acl_map, DeviceMacAddress);

    if (acl_map == NULL) {
        wifi_hal_error_print("%s:%d: MAC %s is not present in acl list\n", __func__, __LINE__, DeviceMacAddress);
        return RETURN_OK;
    }

    hash_map_remove(interface->acl_map, DeviceMacAddress);
    if (acl_map != NULL) {
        free(acl_map);
    }

    if (nl80211_set_acl(interface) != 0) {
        acl_map = (acl_map_t *)malloc(sizeof(acl_map_t));
        /* ---------- start fix 2: the malloc result was used without a check. */
        if (acl_map == NULL) {
            wifi_hal_error_print("%s:%d: memory allocation failure for interface:%s\n", __func__, __LINE__, interface->name);
            return -1;
        }
        /* ---------- end fix 2 */
        wifi_hal_error_print("%s:%d MAC %s nl80211_set_acl failure for interface:%s\n", __func__, __LINE__, DeviceMacAddress, interface->name);
        /* ---------- start fix 3: memcpy always copied sizeof(mac_addr_str_t) = 18 bytes, reading past a shorter string. */
        snprintf(acl_map->mac_addr_str, sizeof(acl_map->mac_addr_str), "%s", DeviceMacAddress);
        /* ---------- end fix 3 */
        to_mac_bytes(acl_map->mac_addr_str, acl_map->mac_addr);

        hash_map_put(interface->acl_map, strdup(DeviceMacAddress), acl_map);

        return -1;
    }

    return 0;
}
}
