/*
 * HANDLER: wifi_hal_findNetworks (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:1234-1310 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It rejects NULL arguments, looks the STA interface
 * up by ap_index, counts the scan-list entries on the requested channel (every entry for channel 0) under the scan mutex, allocates that many wifi_bss_info_t with calloc, copies the entries in
 * list order and returns the array and the number copied.
 *
 * Scaffolding only: get_interface_by_vap_index is a stub over the runner's interfaces; hash_map_count / hash_map_get_first / hash_map_get_next are stubs over the runner's scan lists;
 * ieee80211_freq_to_chan is a table stand-in (2.4 GHz 2412-2472 / 2484, 5 GHz 5170-5885, 6 GHz 5955-7115; unknown frequency -> channel 0, as hostap does); calloc is counted and can be made to fail;
 * the *_print macros go to the log sink hwr_print.  Renamed hwr_sg_wifi_hal_findNetworks.
 */
#include "hwr_wfn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

static void *hwr_wfn_calloc(size_t n, size_t sz)
{
    if (hwr_wfn_world.calloc_fail) return NULL;
    hwr_wfn_world.live_alloc++;
    return calloc(n, sz);
}

#define wifi_hal_error_print(format, ...)        hwr_print(1, format, ##__VA_ARGS__)
#define calloc hwr_wfn_calloc
#define get_interface_by_vap_index hwr_wfn_get_interface_by_vap_index
#define hash_map_count hwr_wfn_hash_map_count
#define hash_map_get_first hwr_wfn_hash_map_get_first
#define hash_map_get_next hwr_wfn_hash_map_get_next
#define ieee80211_freq_to_chan hwr_wfn_ieee80211_freq_to_chan
#define wifi_hal_findNetworks hwr_sg_wifi_hal_findNetworks

hwr_wfn_world_t hwr_wfn_world;

extern "C" {
wifi_interface_info_t *get_interface_by_vap_index(unsigned int vap_index)
{
    for (unsigned int i = 0; i < hwr_wfn_world.num_ifs; i++)
        if (hwr_wfn_world.ifs[i].vap_info.vap_index == vap_index) return &hwr_wfn_world.ifs[i];
    return NULL;
}
uint32_t hash_map_count(hash_map_t *map) { return map->n; }
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
int ieee80211_freq_to_chan(unsigned int freq, u8 *channel)
{
    *channel = 0;
    if (freq >= 2412 && freq <= 2472 && (freq - 2407) % 5 == 0) *channel = (freq - 2407) / 5;
    else if (freq == 2484) *channel = 14;
    else if (freq >= 5170 && freq <= 5885 && freq % 5 == 0) *channel = (freq - 5000) / 5;
    else if (freq >= 5955 && freq <= 7115 && (freq - 5950) % 5 == 0) *channel = (freq - 5950) / 5;
    return *channel ? 1 : 0;
}

/* --- wifi_hal.c:1234-1310 --- */
INT wifi_hal_findNetworks(INT ap_index, wifi_channel_t *channel, wifi_bss_info_t **bss_array, UINT *num_bss)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    wifi_bss_info_t *bss;
    unsigned int num = 0, write_index = 0;
    wifi_bss_info_t *bss_info;
    u8 chan;

    if (!channel || !bss_array || !num_bss) {
        wifi_hal_error_print("%s:%d:invalid parameters\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if ((interface = get_interface_by_vap_index(ap_index)) == NULL) {
        wifi_hal_error_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, ap_index);
        return RETURN_ERR;
    }

    vap = &interface->vap_info;
    if (vap->vap_mode != wifi_vap_mode_sta) {
        wifi_hal_error_print("%s:%d:interface for vap index:%d not found\n", __func__, __LINE__, vap->vap_index);
        return RETURN_ERR;
    }

    // we may need to lock the hash map so that scan results handlers do not change the map
    pthread_mutex_lock(&interface->scan_info_mutex);
    if (channel->channel == 0) {
        num = hash_map_count(interface->scan_info_map);
    } else {
        bss = hash_map_get_first(interface->scan_info_map);
        while (bss != NULL) {
            ieee80211_freq_to_chan(bss->freq, &chan);
            if (chan == channel->channel) {
                num++;
            }
            bss = hash_map_get_next(interface->scan_info_map, bss);
        }
    }

    bss_info = calloc(num, sizeof(wifi_bss_info_t));
    if (!bss_info) {
        pthread_mutex_unlock(&interface->scan_info_mutex);
        wifi_hal_error_print("%s:%d:memory allocation error\n", __func__, __LINE__);
        *bss_array = NULL;
        *num_bss = 0;
        return RETURN_ERR;
    }
    *bss_array = bss_info;
    *num_bss = num;

    bss = hash_map_get_first(interface->scan_info_map);
    while (bss != NULL) {
        bool copy_bss = false;
        if (channel->channel == 0) {
            copy_bss = true;
        } else {
            ieee80211_freq_to_chan(bss->freq, &chan);
            if (chan == channel->channel) {
                copy_bss = true;
            }
        }
        if (copy_bss) {
            if (write_index >= num) {
                wifi_hal_error_print("%s:%d:Scan result count exceeded allocated count\n",__func__, __LINE__);
                break;
            }
            memcpy(&(*bss_array)[write_index],bss,sizeof(wifi_bss_info_t));
            write_index++;
        }
        bss = hash_map_get_next(interface->scan_info_map, bss);
    }
    *num_bss = write_index;
    pthread_mutex_unlock(&interface->scan_info_mutex);

    return RETURN_OK;
}
}
