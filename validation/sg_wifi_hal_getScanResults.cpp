/*
 * HANDLER: wifi_hal_getScanResults (src/wifi_hal.c)
 *
 * Function copied from rdk-wifi-hal (verbatim apart from fix 1): src/wifi_hal.c:1926-2018 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code with fix 1 applied (start fix 1 / end fix 1 markers; the unfixed copy is the reproducer).  It validates the arguments, finds the radio and its STA
 * interface, derives the country string and (channel given) the frequency, counts the scan entries of the STA interface (all of them when the frequency is 0, else those on that frequency), callocs that many
 * wifi_bss_info_t and copies the entries into it.  In the copy loop tmp_bss is advanced for EVERY scan entry but memcpy only runs for the matching ones, so with a frequency filter a match that is not
 * preceded only by matches lands at tmp_bss[index of the entry], not at tmp_bss[number of matches so far].
 *
 * Scaffolding only: get_radio_by_rdk_index / hash_map_* / get_coutry_str_from_code / ieee80211_chan_to_freq are stubs over the runner's world (the country stub keeps the real function's strcpy and
 * "US" default); calloc is counted and can be made to fail; the *_print macros go to the log sink hwr_print.  Renamed hwr_sg_wifi_hal_getScanResults.
 */
#include "hwr_wgs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define wifi_hal_error_print(format, ...)        hwr_print(1, format, ##__VA_ARGS__)
#define get_radio_by_rdk_index hwr_wgs_get_radio_by_rdk_index
#define hash_map_get_first hwr_wgs_hash_map_get_first
#define hash_map_get_next hwr_wgs_hash_map_get_next
#define hash_map_count hwr_wgs_hash_map_count
#define get_coutry_str_from_code hwr_wgs_get_coutry_str_from_code
#define ieee80211_chan_to_freq hwr_wgs_ieee80211_chan_to_freq
#define wifi_hal_getScanResults hwr_sg_wifi_hal_getScanResults

hwr_wgs_world_t hwr_wgs_world;

extern "C" {
void *hwr_wgs_calloc(size_t n, size_t sz)
{
    hwr_wgs_world.calloc_calls++;
    if (hwr_wgs_world.calloc_fail) return NULL;
    return (calloc)(n, sz);
}
wifi_radio_info_t *get_radio_by_rdk_index(wifi_radio_index_t index)
{
    if (hwr_wgs_world.no_radio || index >= HWR_WGS_MAXR) return NULL;
    return &hwr_wgs_world.radios[index];
}
void *hash_map_get_first(void *m)
{
    hash_map_t *map = (hash_map_t *)m;
    if (map == NULL) return NULL;
    map->itr = 0;
    return map->n ? map->items[0] : NULL;
}
void *hash_map_get_next(void *m, void *data)
{
    hash_map_t *map = (hash_map_t *)m;
    if (map == NULL) return NULL;
    map->itr++;
    return map->itr < map->n ? map->items[map->itr] : NULL;
}
unsigned int hash_map_count(hash_map_t *map) { return map->n; }
int get_coutry_str_from_code(wifi_countrycode_type_t code, char *country)
{
    hwr_wgs_world.country_calls++;
    if (code == wifi_countrycode_CA) strcpy(country, "CA");
    else strcpy(country, "US");
    snprintf(hwr_wgs_world.last_country, sizeof(hwr_wgs_world.last_country), "%s", country);
    return 0;
}
int ieee80211_chan_to_freq(const char *country, int op_class, int chan)
{
    hwr_wgs_world.freq_calls++;
    if (chan == 0) return -1;
    if (chan == 255) return 0;
    return chan <= 14 ? 2407 + 5 * chan : 5000 + 5 * chan;
}

#define calloc hwr_wgs_calloc
/* --- wifi_hal.c:1926-2018 --- */
INT wifi_hal_getScanResults(wifi_radio_index_t index, wifi_channel_t *channel, wifi_bss_info_t **bss, UINT *num_bss)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
//    wifi_vap_info_t *vap;
    wifi_radio_operationParam_t *radio_param;
    bool found = false;
    unsigned int freq = 0, total_count = 0;
    char country[8];
    wifi_bss_info_t *scan_info, *tmp_bss;

    if (!channel || !bss || !num_bss) {
        wifi_hal_error_print("%s:%d:invalid parameters\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d: Could not find radio for index: %d\n", __func__, __LINE__, index);
        return RETURN_ERR;
    }

    interface = hash_map_get_first(radio->interface_map);

    while (interface != NULL) {

        if (interface->vap_info.vap_mode == wifi_vap_mode_sta) {
            found = true;
            break;
        }

        interface = hash_map_get_next(radio->interface_map, interface);
    }

    if (found == false) {
        wifi_hal_error_print("%s:%d: Could not find sta interface on radio index: %d, start scan failure\n",
            __func__, __LINE__, index);
        return RETURN_ERR;
    }

//    vap = &interface->vap_info;
    radio_param = &radio->oper_param;

    get_coutry_str_from_code(radio_param->countryCode, country);

    if (channel != NULL) {
        if (radio_param->band != channel->band) {
            wifi_hal_error_print("%s:%d: Channel not valid on radio index: %d band : 0x%x\n", __func__, __LINE__, index, channel->band);
            return RETURN_ERR;
        } else if ((freq = ieee80211_chan_to_freq(country, radio_param->operatingClass, channel->channel)) == -1) {
            wifi_hal_error_print("%s:%d: Channel argument error for index : %d channel : %d\n", __func__, __LINE__, index, channel->channel);
            return RETURN_ERR;
        }
    }

    pthread_mutex_lock(&interface->scan_info_mutex);
    if (freq == 0) {
        total_count = hash_map_count(interface->scan_info_map);
    } else {
        scan_info = hash_map_get_first(interface->scan_info_map);
        while (scan_info != NULL) {
            if (freq == scan_info->freq) total_count++;
            scan_info = hash_map_get_next(interface->scan_info_map, scan_info);
        }
    }

    tmp_bss = calloc(total_count, sizeof(wifi_bss_info_t));
    if (!tmp_bss) {
        pthread_mutex_unlock(&interface->scan_info_mutex);
        wifi_hal_error_print("%s:%d:memory allocation error\n", __func__, __LINE__);
        *bss = NULL;
        *num_bss = 0;
        return RETURN_ERR;
    }
    *bss = tmp_bss;
    *num_bss = total_count;

    scan_info = hash_map_get_first(interface->scan_info_map);
    while (scan_info != NULL) {
        if (freq == 0) {
            memcpy(tmp_bss, scan_info, sizeof(wifi_bss_info_t));
            tmp_bss++;
        } else {
            if (freq == scan_info->freq) {
                memcpy(tmp_bss, scan_info, sizeof(wifi_bss_info_t));
                /* ---------- start fix 1: tmp_bss was advanced for every scan entry, so a match that came after a
                 * non-matching one was written at its scan index, past the total_count entries allocated. Advance
                 * only when an entry was copied. */
                tmp_bss++;
                /* ---------- end fix 1 */
            }
        }
        scan_info = hash_map_get_next(interface->scan_info_map, scan_info);
    }
    pthread_mutex_unlock(&interface->scan_info_mutex);

    return RETURN_OK;
}
}
