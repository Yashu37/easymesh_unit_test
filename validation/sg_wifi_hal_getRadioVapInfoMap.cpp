/*
 * HANDLER: wifi_hal_getRadioVapInfoMap (src/wifi_hal.c)
 *
 * Function copied from rdk-wifi-hal (verbatim apart from fix 1): src/wifi_hal.c:1843-1891 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code with fix 1 applied (start fix 1 / end fix 1 markers; the unfixed copy is the reproducer).  It validates the radio index and map, looks the radio up,
 * and for every interface of the radio's interface map with a non-negative vap_index copies the interface's vap info into map->vap_array[itr] (itr counted from 0), stores the interface MAC as the sta mac
 * (names sim_sta* / mesh_sta*) or as the bssid (every other name) and finally sets map->num_vaps = itr.  itr is never compared with the size of map->vap_array.
 *
 * Scaffolding only: get_radio_by_rdk_index / hash_map_get_first / hash_map_get_next are stubs over the runner's radios and interfaces; the *_print macros go to the log sink hwr_print.  Renamed
 * hwr_sg_wifi_hal_getRadioVapInfoMap.
 */
#include "hwr_wvm.h"
#include <stdio.h>
#include <string.h>

#define wifi_hal_error_print(format, ...)        hwr_print(1, format, ##__VA_ARGS__)
#define get_radio_by_rdk_index hwr_wvm_get_radio_by_rdk_index
#define hash_map_get_first hwr_wvm_hash_map_get_first
#define hash_map_get_next hwr_wvm_hash_map_get_next
#define wifi_hal_getRadioVapInfoMap hwr_sg_wifi_hal_getRadioVapInfoMap

/* src/wifi_hal.c:62-94 (non-emulator variant) */
#define RADIO_INDEX_ASSERT_RC(radioIndex, retcode) \
    do { \
        int _index = (int)radioIndex; \
        if ((_index >= (MAX_NUM_RADIOS)) || (_index < 0)) { \
            wifi_hal_error_print("%s: INCORRECT radioIndex = %d numRadios = %d\n", \
                    __FUNCTION__, _index, MAX_NUM_RADIOS); \
            return retcode; \
        } \
    } while (0)
#define NULL_PTR_ASSERT_RC(ptr, retcode) \
    do { \
        if (NULL == ptr) { \
            wifi_hal_error_print("%s:%d NULL pointer!\n", __FUNCTION__, __LINE__); \
            return retcode; \
        } \
    } while (0)
#define RADIO_INDEX_ASSERT(radioIndex)  RADIO_INDEX_ASSERT_RC(radioIndex, WIFI_HAL_INVALID_ARGUMENTS)
#define NULL_PTR_ASSERT(ptr)            NULL_PTR_ASSERT_RC(ptr, WIFI_HAL_INVALID_ARGUMENTS)

hwr_wvm_world_t hwr_wvm_world;

extern "C" {
wifi_radio_info_t *get_radio_by_rdk_index(unsigned int index)
{
    if (hwr_wvm_world.no_radio || index >= HWR_WVM_MAXR) return NULL;
    return &hwr_wvm_world.radios[index];
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

/* --- wifi_hal.c:1843-1891 --- */
INT wifi_hal_getRadioVapInfoMap(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
    unsigned int itr = 0;
    wifi_interface_info_t *interface = NULL;
    wifi_radio_info_t *radio =  NULL;

    RADIO_INDEX_ASSERT(index);
    NULL_PTR_ASSERT(map);

    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d: Could not find radio index:%d\n", __func__, __LINE__, index);
        return RETURN_ERR;
    }

    if (radio->interface_map == NULL) {
        wifi_hal_error_print("%s:%d: No interface map is empty for radio index:%d\n", __func__, __LINE__, index);
        return RETURN_ERR;
    }

    interface = hash_map_get_first(radio->interface_map);
    if (interface == NULL ) {
        wifi_hal_error_print("%s:%d: Interface map is empty for radio\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    while (interface != NULL) {
        // on CMXB7 platform radio interfaces have vap_index -1
        // therefore check for interface vap_index
        // and don't add radio interfaces to vap map
        if ((int)interface->vap_info.vap_index >= 0){
            /* ---------- start fix 1: itr was never compared with the vap_array size, so a radio with more than
             * MAX_NUM_VAP_PER_RADIO VAP interfaces was written past the end of the map. */
            if (itr >= (sizeof(map->vap_array) / sizeof(map->vap_array[0]))) {
                wifi_hal_error_print("%s:%d: radio index:%d has more than %u vaps, the rest are not copied\n", __func__, __LINE__,
                    index, (unsigned int)(sizeof(map->vap_array) / sizeof(map->vap_array[0])));
                break;
            }
            /* ---------- end fix 1 */
            memcpy(&map->vap_array[itr], &interface->vap_info, sizeof(wifi_vap_info_t));
            if (strncmp((char *)map->vap_array[itr].vap_name, "sim_sta", strlen("sim_sta")) == 0) {
                memcpy(map->vap_array[itr].u.sta_info.mac, interface->mac, sizeof(map->vap_array[itr].u.sta_info.mac));
            } else if (strncmp((char *)map->vap_array[itr].vap_name, "mesh_sta", strlen("mesh_sta")) != 0) {
                memcpy(map->vap_array[itr].u.bss_info.bssid, interface->mac, sizeof(map->vap_array[itr].u.bss_info.bssid));
            } else {
                memcpy(map->vap_array[itr].u.sta_info.mac, interface->mac, sizeof(map->vap_array[itr].u.sta_info.mac));
            }

            itr++;
        }
        interface = hash_map_get_next(radio->interface_map, interface);
    }

    map->num_vaps = itr;

    return RETURN_OK;
}
}
