/*
 * HANDLER: wifi_hal_startScan (src/wifi_hal.c)
 *
 * Function copied from rdk-wifi-hal (verbatim apart from fix 1): src/wifi_hal.c:2488-2612 (~/Desktop/G/rdk-wifi-hal), generic build (no _PLATFORM_BANANAPI_R4_, FEATURE_SINGLE_PHY not defined).  This file holds the ORIGINAL code with fix 1 applied (start fix 1 / end fix 1 markers; the unfixed copy is the reproducer).  It validates index / dwell_time, finds the STA interface of the radio, turns the requested channels (the radio's own channel for ONCHAN, chan_list[0..num-1] for OFFCHAN) into a
 * frequency list (freq_list[MAX_FREQ_LIST_SIZE]) while building the log string chan_list_str[512], flushes the interface's scan results, sets radio->rnr_enabled when a radio is 6 GHz and starts the scan.
 *
 * Scaffolding only: get_radio_by_rdk_index / hash_map_* / get_coutry_str_from_code / get_op_class_from_radio_params / ieee80211_chan_to_freq / nl80211_start_scan are stubs over the runner's world;
 * get_vap_ssid is the real function (wifi_hal_nl80211_utils.c:1557); malloc / free are counted; g_wifi_hal is the stand-in hwr_wss_world.hal; the *_print macros go to the log sink hwr_print.
 * Renamed hwr_sg_wifi_hal_startScan.
 */
#include "hwr_wss.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/nl80211.h>

#define MAX_FREQ_LIST_SIZE 128

hwr_wss_world_t hwr_wss_world;

/* counted allocator (defined before malloc / free are redirected to it) */
static void *hwr_wss_malloc(size_t n)
{
    hwr_wss_world.malloc_calls++;
    if (hwr_wss_world.malloc_fail) return NULL;
    hwr_wss_world.live_alloc++;
    return calloc(1, n);
}
static void hwr_wss_free(void *p)
{
    if (p) { hwr_wss_world.live_alloc--; hwr_wss_world.free_calls++; }
    free(p);
}

#define wifi_hal_stats_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_stats_info_print(format, ...)   hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_stats_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)        hwr_print(1, format, ##__VA_ARGS__)
#define g_wifi_hal hwr_wss_world.hal
#define malloc hwr_wss_malloc
#define free hwr_wss_free
#define get_radio_by_rdk_index hwr_wss_get_radio_by_rdk_index
#define hash_map_get_first hwr_wss_hash_map_get_first
#define hash_map_get_next hwr_wss_hash_map_get_next
#define hash_map_cleanup hwr_wss_hash_map_cleanup
#define get_coutry_str_from_code hwr_wss_get_coutry_str_from_code
#define get_op_class_from_radio_params hwr_wss_get_op_class_from_radio_params
#define ieee80211_chan_to_freq hwr_wss_ieee80211_chan_to_freq
#define get_vap_ssid hwr_wss_get_vap_ssid
#define nl80211_start_scan hwr_wss_nl80211_start_scan
#define wifi_hal_startScan hwr_sg_wifi_hal_startScan

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
#define RADIO_INDEX_ASSERT(radioIndex)  RADIO_INDEX_ASSERT_RC(radioIndex, WIFI_HAL_INVALID_ARGUMENTS)

extern "C" {
wifi_radio_info_t *get_radio_by_rdk_index(unsigned int index)
{
    if (hwr_wss_world.no_radio || index >= HWR_WSS_MAXR) return NULL;
    return &hwr_wss_world.hal.radio_info[index];
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
void hash_map_cleanup(hash_map_t *map) { hwr_wss_world.cleanup_calls++; }
int get_coutry_str_from_code(wifi_countrycode_type_t code, char *country)
{
    hwr_wss_world.country_calls++;
    strcpy(country, "US");
    return 0;
}
int get_op_class_from_radio_params(wifi_radio_operationParam_t *param)
{
    if ((unsigned)param->countryCode > (unsigned)wifi_countrycode_ZW) return -1;
    if (param->channel == 0 || param->channel > 233) return -1;
    return 115;
}
int ieee80211_chan_to_freq(const char *country, int op_class, int chan)
{
    if (chan == 255) return 0;
    return chan <= 14 ? 2407 + 5 * chan : 5000 + 5 * chan;
}
/* wifi_hal_nl80211_utils.c:1557 */
const char *get_vap_ssid(wifi_vap_info_t *vap)
{
    return (vap->u.sta_info.ignite_enabled) ? vap->u.sta_info.repurposed_ssid : vap->u.sta_info.ssid;
}
int nl80211_start_scan(wifi_interface_info_t *interface, unsigned int flags, unsigned int num_freq, unsigned int *freq_list, unsigned int dwell_time, unsigned int num_ssid, ssid_t *ssid_list)
{
    hwr_wss_world_t *w = &hwr_wss_world;
    w->start_calls++; w->last_iface = interface; w->last_flags = flags; w->last_nfreq = (int)num_freq; w->last_dwell = (int)dwell_time; w->last_nssid = (int)num_ssid;
    for (unsigned i = 0; i < num_freq && i < HWR_WSS_FREQ_REC; i++) w->last_freqs[i] = freq_list[i];
    memcpy(w->last_ssid0, ssid_list[0], 32); w->last_ssid0[32] = '\0';
    return w->start_ret;
}

/* --- wifi_hal.c:2488-2612 --- */
INT wifi_hal_startScan(wifi_radio_index_t index, wifi_neighborScanMode_t scan_mode, INT dwell_time, UINT num, UINT *chan_list)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    bool found = false;
    wifi_radio_operationParam_t *radio_param = NULL, *param = NULL;
    char country[8] = {0}, tmp_str[32] = {0}, chan_list_str[512] = {0};
    unsigned int freq_list[MAX_FREQ_LIST_SIZE], i;
    ssid_t  ssid_list[8];
    int op_class, freq_num = 0;

    wifi_hal_stats_dbg_print("%s:%d: index: %d mode: %d dwell time: %d\n", __func__, __LINE__, index,
        scan_mode, dwell_time);

    RADIO_INDEX_ASSERT(index);

    if (dwell_time < 0) {
        wifi_hal_stats_error_print("%s:%d: invalide dwell time: %d\n", __func__, __LINE__, dwell_time);
        return WIFI_HAL_INVALID_ARGUMENTS;
    }

    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        wifi_hal_stats_error_print("%s:%d:Could not find radio for index: %d\n", __func__, __LINE__, index);
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
        wifi_hal_stats_error_print("%s:%d:Could not find sta interface on radio index: %d, start scan failure\n", 
            __func__, __LINE__, index);
        return RETURN_ERR;
    }

#if defined(_PLATFORM_BANANAPI_R4_)
    if (interface->rdk_radio_index != index) {
        wifi_hal_stats_error_print("%s:%d:Not allowing scan on radio_index: %d because not "
            "matching with interface->rdk_radio_index:%d\n",
            __func__, __LINE__, index, interface->rdk_radio_index);
        return RETURN_ERR;
    }
#endif

    vap = &interface->vap_info;
    radio_param = &radio->oper_param;

    if (scan_mode == WIFI_RADIO_SCAN_MODE_ONCHAN) {
        num = 1;
    } else if (scan_mode == WIFI_RADIO_SCAN_MODE_OFFCHAN) {
        if ((num == 0) || (chan_list == NULL)) {
            wifi_hal_stats_error_print("%s:%d: Channels not speified for offchannel scan mode\n", __func__, __LINE__);
            return RETURN_ERR; 
        }
    } else {
        wifi_hal_stats_error_print("%s:%d: Incorrect scan mode\n", __func__, __LINE__);
        return RETURN_ERR; 
    }

    get_coutry_str_from_code(radio_param->countryCode, country);
    param = (wifi_radio_operationParam_t *)malloc(sizeof(wifi_radio_operationParam_t));
    if (param == NULL) {
        wifi_hal_error_print("%s:%d: malloc failed\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    memcpy((unsigned char *)param, (unsigned char *)radio_param, sizeof(wifi_radio_operationParam_t));

    param->channelWidth = WIFI_CHANNELBANDWIDTH_20MHZ;

    for (i = 0; i < num && freq_num < MAX_FREQ_LIST_SIZE; i++) {
        param->channel = (scan_mode == WIFI_RADIO_SCAN_MODE_ONCHAN) ?
            radio_param->channel : chan_list[i]; 

        if ((op_class = get_op_class_from_radio_params(param)) == -1) {
            wifi_hal_stats_error_print("%s:%d: Invalid channel %d\n", __func__, __LINE__, param->channel);
            continue;
        }

        freq_list[freq_num] = ieee80211_chan_to_freq(country, op_class, param->channel);
        if (freq_list[freq_num] == 0) {
            continue;
        }
        sprintf(tmp_str, "%d ", freq_list[freq_num]);
        /* ---------- start fix 1: chan_list_str[512] overflowed with 103+ usable channels (5 chars each); the string is only logged, so stop appending when it is full. */
        if (strlen(chan_list_str) + strlen(tmp_str) < sizeof(chan_list_str)) {
            strcat(chan_list_str, tmp_str);
        }
        /* ---------- end fix 1 */

	freq_num++;
    }

    free(param);
    param = NULL;

    if (freq_num == 0) {
        wifi_hal_stats_error_print("%s:%d: No valid channels\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    
    strcpy(ssid_list[0], get_vap_ssid(vap));
    wifi_hal_stats_info_print("%s:%d: Scan Frequencies:%s \n", __func__, __LINE__, chan_list_str);

    pthread_mutex_lock(&interface->scan_info_mutex);
    hash_map_cleanup(interface->scan_info_map);
    pthread_mutex_unlock(&interface->scan_info_mutex);

#ifndef FEATURE_SINGLE_PHY
    for (unsigned int r = 0; r < g_wifi_hal.num_radios; r++) {
        if (g_wifi_hal.radio_info[r].oper_param.band == WIFI_FREQUENCY_6_BAND) {
            radio->rnr_enabled = true;
            break;
        }
    }
#endif //FEATURE_SINGLE_PHY

    return (nl80211_start_scan(interface, NL80211_SCAN_FLAG_COLOCATED_6GHZ | NL80211_SCAN_FLAG_FLUSH, freq_num, freq_list, dwell_time, 1, ssid_list) == 0) ? RETURN_OK:RETURN_ERR;
}
}
