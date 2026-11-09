/*
 * HANDLER: wifi_startNeighborScan
 *
 * Functions copied from rdk-wifi-hal (~/Desktop/G/rdk-wifi-hal): the banana-pi forwarder wifi_startNeighborScan
 * (platform/banana-pi/platform.c:560), which only calls wifi_hal_startNeighborScan (src/wifi_hal.c:3147-3585, where all the
 * logic is), plus the helpers it uses with OPTION_GET_CHANNELS_FROM_HOSTAP == 1 and CONFIG_NEIGHBOR_AP_SCAN_ACTIVE == 0
 * exactly as in wifi_hal.c: set_freqs_filter / cleanup_freqs_filter (2636-2644), channel_is_valid_from_hapd and
 * get_valid_freqs_list_from_hapd (2748-2830), uint_array_set (wifi_hal_nl80211_utils.c:4798, verbatim).
 * This file holds the ORIGINAL (unfixed) code, so the harness reproduces the crashes.
 *
 * Scaffolding only (the real types need the hostap / driver header tree, see hwr_wsn.h):
 *  - reduced wifi_interface_info_t / wifi_radio_info_t / hostapd structures with just the fields the function touches.
 *  - get_interface_by_vap_index / get_radio_by_rdk_index / get_private_vap_interface: runner-controlled lookups.
 *  - get_coutry_str_from_code (real body over a reduced map, unknown -> "US"), wifi_channel_to_freq (real body) over an
 *    ieee80211_chan_to_freq table, country_to_global_op_class (only used for a debug print).
 *  - nl80211_start_scan / nl80211_get_scan_results: recording stubs (nl80211 is a netlink call).
 *  - the *_print macros are mapped to the log sink hwr_print (runner-poisoned slot).
 */
#include "hwr_wsn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define wifi_hal_dbg_print(format, ...)          hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)        hwr_print(1, format, ##__VA_ARGS__)
#define wifi_hal_stats_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_stats_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define wifi_hal_stats_info_print(format, ...)   hwr_print(0, format, ##__VA_ARGS__)

#define wifi_interface_info_t   wsn_interface_t
#define wifi_radio_info_t       wsn_radio_t
#define uint_array_t            wsn_uint_array_t
#define hostapd_data            wsn_hapd_t
#define hostapd_iface           wsn_hiface_t
#define hostapd_hw_modes        wsn_hw_mode_t
#define HOSTAPD_CHAN_DISABLED   WSN_CHAN_DISABLED
#define wifi_hal_startNeighborScan hwr_wifi_hal_startNeighborScan
#define NL80211_SCAN_FLAG_FLUSH (1 << 1)
#define NL80211_SCAN_FLAG_AP    (1 << 2)
#define OPTION_FILTER_DISABLED_CHANNELS 1
#define OPTION_GET_CHANNELS_FROM_HOSTAP 1
#define CONFIG_NEIGHBOR_AP_SCAN_ACTIVE  0
#define ARRAY_SZ(x) (sizeof(x) / sizeof((x)[0]))
typedef unsigned int uint;
/* src/wifi_hal_priv.h:447-458 */
enum { WIFI_SCAN_STATE_NONE, WIFI_SCAN_STATE_ERROR, WIFI_SCAN_STATE_STARTED, WIFI_SCAN_STATE_ABORTED };
#define WIFI_SCAN_RES_COLLECTED_API   0x01

wsn_world_t hwr_wsn_world;
static struct { pthread_mutex_t hapd_lock; } g_wifi_hal = { PTHREAD_MUTEX_INITIALIZER };

static wsn_interface_t *get_interface_by_vap_index(unsigned int vap_index)
{
    return (hwr_wsn_world.ap_iface && hwr_wsn_world.ap_vap_index == vap_index) ? hwr_wsn_world.ap_iface : NULL;
}
static wsn_radio_t *get_radio_by_rdk_index(unsigned int index)
{
    return (hwr_wsn_world.radio && hwr_wsn_world.radio_index == index) ? hwr_wsn_world.radio : NULL;
}
static wsn_interface_t *get_private_vap_interface(wsn_radio_t *radio)
{
    (void)radio;
    return hwr_wsn_world.priv_iface;
}
static void hash_map_cleanup(void *map) { (void)map; hwr_wsn_world.cleanup_calls++; }
static int wifi_strcpy(char *dest, size_t dest_size, const char *src)
{
    if (strlen(src) + 1 > dest_size) return -1;
    strcpy(dest, src);
    return 0;
}
static unsigned country_to_global_op_class(const char *country, unsigned char op_class) { (void)country; return op_class; }
static int get_coutry_str_from_code(int code, char *country)
{
    static const struct { int c; const char *s; } map[] = { {1,"US"}, {2,"CA"}, {3,"JP"}, {4,"CN"}, {5,"DE"}, {6,"GB"} };
    int value_updated = 0;
    for (unsigned i = 0; i < sizeof(map)/sizeof(map[0]); i++)
        if (map[i].c == code) { strcpy(country, map[i].s); value_updated = 1; break; }
    if (!value_updated) strcpy(country, "US");
    return RETURN_OK;
}
static int ieee80211_chan_to_freq(const char *country, unsigned char op_class, unsigned char chan)
{
    (void)country;
    switch (op_class) {
    case 81:  return (chan >= 1 && chan <= 13) ? 2407 + 5 * chan : -1;            /* 2.4 GHz */
    case 115: case 118: case 121: case 124: case 125: case 128: case 129: case 130:   /* 5 GHz */
        return (chan >= 36 && chan <= 177) ? 5000 + 5 * chan : -1;
    }
    return -1;
}
/* --- copied from wifi_hal_nl80211_utils.c:4843 --- */
static int wifi_channel_to_freq(const char* country, unsigned char opclass, uint channel, uint *freq)
{
    int ifreq = ieee80211_chan_to_freq(country, opclass, channel);
    *freq = (uint)ifreq;
    return (ifreq < 0) ? RETURN_ERR : RETURN_OK;
}
/* wifi_freq_to_channel: only used for a debug print of the FULL scan list */
static int wifi_freq_to_channel(int freq, uint *channel)
{
    *channel = (freq >= 5000) ? (uint)((freq - 5000) / 5) : (uint)((freq - 2407) / 5);
    return RETURN_OK;
}
/* nl80211_start_scan: record the call (flags / filter / dwell / active) and return the configured result */
static int nl80211_start_scan(wsn_interface_t *interface, unsigned int flags, unsigned int num_freq, unsigned int *freq_list,
    int dwell_time, int num_ssids, void *ssids)
{
    (void)interface; (void)ssids;
    hwr_wsn_world.start_calls++;
    hwr_wsn_world.start_flags = flags;
    hwr_wsn_world.start_num = num_freq;
    hwr_wsn_world.start_dwell = dwell_time;
    hwr_wsn_world.start_active = num_ssids;
    hwr_wsn_world.start_ssid[0] = 0;
    if (num_ssids == 1 && ssids) snprintf(hwr_wsn_world.start_ssid, sizeof(hwr_wsn_world.start_ssid), "%s", (const char *)ssids);
    for (unsigned i = 0; i < num_freq && i < 16; i++) hwr_wsn_world.start_values[i] = freq_list[i];
    return hwr_wsn_world.nl_start_rc;
}
/* nl80211_get_scan_results: record the state / filter it sees; on success the real one moves the scan on (state NONE here) */
static int nl80211_get_scan_results(wsn_interface_t *interface)
{
    hwr_wsn_world.results_calls++;
    hwr_wsn_world.state_at_results = interface->scan_state;
    hwr_wsn_world.start_num = interface->scan_filter.num;
    for (unsigned i = 0; i < interface->scan_filter.num && i < 16; i++) hwr_wsn_world.start_values[i] = interface->scan_filter.values[i];
    if (hwr_wsn_world.nl_results_rc == 0) interface->scan_state = 0;
    return hwr_wsn_world.nl_results_rc;
}

/* --- copied from wifi_hal_nl80211_utils.c:4798 --- */
static int uint_array_set(uint_array_t *array, uint num, const uint values[])
{
    int ret = 0;
    if (array == NULL) return -1;

    if (num == 0)
        goto cleanup_array;

    /* Reallocate array if needed */
    if (num != array->num) {
        free(array->values);
        array->values = (uint*)malloc(num * sizeof(uint));
        if (array->values == NULL) {
            wifi_hal_stats_error_print("%s:%d: memory allocation error!\n", __func__, __LINE__);
            ret = -1;
            goto cleanup_array;
        }
        array->num = num;
    }

    /* Copy freq data to the array entry */
    if (values) {
        memcpy(array->values, values, num * sizeof(uint));
    } else {
        memset(array->values, 0, num * sizeof(uint));
    }
    return 0;

cleanup_array:
    free(array->values);
    array->values = NULL;
    array->num = 0;
    return ret;
}

/* --- copied from wifi_hal.c:2636 --- */
static inline int set_freqs_filter(wifi_interface_info_t *interface, uint num_freqs, const uint freqs[])
{
    return uint_array_set(&interface->scan_filter, num_freqs, freqs);
}

static inline void cleanup_freqs_filter(wifi_interface_info_t *interface)
{
    uint_array_set(&interface->scan_filter, 0, NULL);
}
extern "C" void hwr_wsn_cleanup_filter(wsn_interface_t *interface) { cleanup_freqs_filter(interface); }

static const char *get_chan_dfs_state(wsn_chan_t *c) { (void)c; return "n/a"; }

/* --- copied from wifi_hal.c:2748 (hapd variant) --- */
/* Returns freq corresponding to the channel or -1 if channel is not valid */
static int channel_is_valid_from_hapd(hostapd_data *hapd, unsigned channel)
{
    int i;
    hostapd_iface *iface = hapd->iface;
    
    hostapd_hw_modes *feature = iface->current_mode;

    if (feature == NULL) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] iface->current_mode is NULL\n", __func__, __LINE__);
        return -1;
    }

    for (i = 0; i < feature->num_channels; ++i) {
        if ((int)channel == feature->channels[i].chan) {
            bool enabled = (feature->channels[i].flag & HOSTAPD_CHAN_DISABLED) ? false : true;
            int freq = feature->channels[i].freq;
            wifi_hal_stats_dbg_print("%s:%d: [SCAN] \tchannel=%u, %s, dfs:%s\n", __func__, __LINE__,
                channel, enabled ? "enabled" : "disabled",
                get_chan_dfs_state(&feature->channels[i]));
#if OPTION_FILTER_DISABLED_CHANNELS
            return enabled ? freq : -1;
#else
            return freq;
#endif
        }
    }

    return -1;
}

static int get_valid_freqs_list_from_hapd(hostapd_data *hapd, uint_array_t* freqs)
{
    int i;
    hostapd_iface *iface = hapd->iface;
    
    hostapd_hw_modes *feature = iface->current_mode;
    uint count = 0;
    uint *list;

    if (feature == NULL) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] iface->current_mode is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

#if OPTION_FILTER_DISABLED_CHANNELS
    // - count available channels
    for (i = 0; i < feature->num_channels; ++i) {
        if ( !(feature->channels[i].flag & HOSTAPD_CHAN_DISABLED) )
            ++count;
    }
#else
    count = feature->num_channels;
#endif

    // - allocate array
    if (RETURN_OK != uint_array_set(freqs, count, NULL))
        return RETURN_ERR;

    // - copy enabled freq
    list = freqs->values;
    for (i = 0; i < feature->num_channels; ++i) {
#if OPTION_FILTER_DISABLED_CHANNELS
        if ( !(feature->channels[i].flag & HOSTAPD_CHAN_DISABLED) )
            *list++ = feature->channels[i].freq;
#else
        *list++ = feature->channels[i].freq;
#endif
    }
    return RETURN_OK;
}

#define AP_INDEX_ASSERT_RC(apIndex, retcode) \
    do { \
        int _index = (int)apIndex; \
        if ((_index >= (MAX_VAP)) || (_index < 0)) { \
            wifi_hal_error_print("%s, INCORRECT apIndex = %d MAX_VAP = %d\n", __FUNCTION__, \
                            _index, MAX_VAP); \
            return retcode; \
        } \
    } while (0)
#define AP_INDEX_ASSERT(apIndex)        AP_INDEX_ASSERT_RC(apIndex, WIFI_HAL_INVALID_ARGUMENTS)

/* --- copied from wifi_hal.c:3147 --- */
static INT wifi_hal_startNeighborScan(INT apIndex, wifi_neighborScanMode_t scan_mode, INT dwell_time,
    UINT chan_num, UINT *chan_list)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
    uint freq, op_class;
    uint i;
    char country[8] = { 0 };
    bool is_ap_mode = false;
    int radioIndex, res;
    ssid_t ssid_list[1] = { "" };
    bool is_active_scan = false;
    uint current_channel = 0;

    wifi_hal_stats_dbg_print("%s:%d: [SCAN] == ENTER (mode:%u, dwell_time:%d) ==\n", __func__,
        __LINE__, scan_mode, dwell_time);

    if (dwell_time < 0) {
        wifi_hal_stats_error_print("%s:%d: invalid dwell time: %d\n", __func__, __LINE__,
            dwell_time);
        return WIFI_HAL_INVALID_ARGUMENTS;
    }

    AP_INDEX_ASSERT(apIndex);

    interface = get_interface_by_vap_index(apIndex);
    if (interface == NULL) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] interface for AP index:%d not found\n", __func__,
            __LINE__, apIndex);
        return WIFI_HAL_ERROR;
    }

    radioIndex = interface->vap_info.radio_index;
    radio = get_radio_by_rdk_index(radioIndex);
    if (radio == NULL) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] radio for radio index:%d not found\n", __func__,
            __LINE__, radioIndex);
        return WIFI_HAL_ERROR;
    }

    is_ap_mode = (interface->vap_info.vap_mode == wifi_vap_mode_ap);

    if (RETURN_OK != get_coutry_str_from_code(radio->oper_param.countryCode, country)) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] Cant find country string (county:%u)\n", __func__,
            __LINE__, radio->oper_param.countryCode);
        return RETURN_ERR;
    }

    op_class = radio->oper_param.operatingClass;
    {
        unsigned global_op_class = country_to_global_op_class(country, op_class);
        wifi_hal_stats_dbg_print(
            "%s:%d: [SCAN] country code: %s, op_class:%d, global_op_class:%d\n", __func__, __LINE__,
            country, op_class, global_op_class);
    }

    /* Scanning is performed for the radio, so the status and results of the scan are stored in the
     * primary/private interface */

#if OPTION_GET_CHANNELS_FROM_HOSTAP == 0
    interface = get_primary_interface(radio);
    if (interface == NULL) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] primary interface for radio '%s' not found\n",
            __func__, __LINE__, radio->name);
        return WIFI_HAL_ERROR;
    }
#else
    interface = get_private_vap_interface(radio);
    if (interface == NULL) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] private interface for radio '%s' not found\n",
            __func__, __LINE__, radio->name);
        return WIFI_HAL_ERROR;
    }
#endif

    pthread_mutex_lock(&interface->scan_state_mutex);
    {
        wifi_hal_stats_dbg_print("%s:%d: [SCAN] scan_state:%d\n", __func__, __LINE__,
            interface->scan_state);

        if (interface->scan_has_results & WIFI_SCAN_RES_COLLECTED_API) {
            wifi_hal_stats_dbg_print(
                "%s:%d: [SCAN] Starting new scan, although results for radio %d "
                "(%s) from previous scan weren't collected\n",
                __func__, __LINE__, radioIndex, interface->name);
        }

        // - Check if scan was already triggered and is in progress
        if (interface->scan_state == WIFI_SCAN_STATE_STARTED) {
            pthread_mutex_unlock(&interface->scan_state_mutex);
            wifi_hal_stats_dbg_print("%s:%d: [SCAN] Scan already triggered for radio %d (%s)\n",
                __func__, __LINE__, radioIndex, interface->name);
            return WIFI_HAL_INTERNAL_ERROR;
        }

        // - Reset state before scanning
        interface->scan_state = WIFI_SCAN_STATE_NONE;

        /* Cleanup scan data (scan_info_ap_map[0]) before the new scan. Result data
         *  (scan_info_ap_map[1]) stays unchanged.
         */
        pthread_mutex_lock(&interface->scan_info_mutex);
        hash_map_cleanup(interface->scan_info_map);
        pthread_mutex_unlock(&interface->scan_info_mutex);
        pthread_mutex_lock(&interface->scan_info_ap_mutex);
        cleanup_freqs_filter(interface);
        hash_map_cleanup(interface->scan_info_ap_map[0]);
        pthread_mutex_unlock(&interface->scan_info_ap_mutex);
    }
    pthread_mutex_unlock(&interface->scan_state_mutex);

    if ((scan_mode == WIFI_RADIO_SCAN_MODE_ONCHAN) && (dwell_time == 0)) {
        // - special case:
        wifi_hal_stats_dbg_print(
            "%s:%d: [SCAN] On channel scan with dwell time 0 => not triggering "
            "scan, requesting scan results immediately\n",
            __func__, __LINE__);

        // - get the current channel
        if (chan_num == 0 || chan_list == NULL) {
            chan_num = 1;
            current_channel = radio->oper_param.channel;
        }

        // - allocate space for freq list
        if (RETURN_OK != set_freqs_filter(interface, chan_num, NULL))
            return WIFI_HAL_ERROR;

        // - convert channels to freqs
        for (i = 0; i < chan_num; i++) {
            if (is_ap_mode) {
                // - verify the channel number (it is possible only in AP mode)
                int i_freq;
#if OPTION_GET_CHANNELS_FROM_HOSTAP == 0
                if (current_channel != 0) {
                    i_freq = channel_is_valid_from_radio(radio, current_channel);
                } else {
                    i_freq = channel_is_valid_from_radio(radio, chan_list[i]);
                }
#else
                pthread_mutex_lock(&g_wifi_hal.hapd_lock);
                if (current_channel != 0) {
                    i_freq = channel_is_valid_from_hapd(&interface->u.ap.hapd, current_channel);
                } else {
                    i_freq = channel_is_valid_from_hapd(&interface->u.ap.hapd, chan_list[i]);
                }
                pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
#endif // OPTION_GET_CHANNELS_FROM_HOSTAP
                if (i_freq < 0) {
                    if (current_channel != 0) {
                        wifi_hal_stats_error_print(
                            "%s:%d: [SCAN] channel %u is invalid for radio %d\n", __func__,
                            __LINE__, current_channel, radioIndex);
                    } else {
                        wifi_hal_stats_error_print(
                            "%s:%d: [SCAN] channel %u is invalid for radio %d\n", __func__,
                            __LINE__, chan_list[i], radioIndex);
                    }
                    return WIFI_HAL_ERROR;
                }
                freq = i_freq;
            } else {
                if (current_channel != 0) {
                    if (RETURN_OK !=
                        wifi_channel_to_freq(country, op_class, current_channel, &freq)) {
                        wifi_hal_stats_error_print(
                            "%s:%d: [SCAN] Couldn't get frequency for channel %u\n", __func__,
                            __LINE__, current_channel);
                        return WIFI_HAL_ERROR;
                    }
                } else {
                    if (RETURN_OK != wifi_channel_to_freq(country, op_class, chan_list[i], &freq)) {
                        wifi_hal_stats_error_print(
                            "%s:%d: [SCAN] Couldn't get frequency for channel %u\n", __func__,
                            __LINE__, chan_list[i]);
                        return WIFI_HAL_ERROR;
                    }
                }

                interface->scan_filter.values[i] = freq;
                if (current_channel != 0) {
                    wifi_hal_stats_dbg_print("%s:%d: [SCAN] chan:%u -> freq:%u (current channel)\n",
                        __func__, __LINE__, current_channel, freq);
                } else {
                    wifi_hal_stats_dbg_print("%s:%d: [SCAN] chan:%u -> freq:%u\n", __func__,
                        __LINE__, chan_list[i], freq);
                }
            }

            pthread_mutex_lock(&interface->scan_state_mutex);
            interface->scan_state = WIFI_SCAN_STATE_STARTED;
            pthread_mutex_unlock(&interface->scan_state_mutex);
        }
        // - scan_state is changed by nl80211_get_scan_results()
        if (nl80211_get_scan_results(interface) != RETURN_OK)
            return WIFI_HAL_ERROR;

        return WIFI_HAL_SUCCESS;
    }

    wifi_hal_stats_dbg_print("%s:%d: [SCAN] oper_param.opclass:%d, oper_param.channel:%d\n",
        __func__, __LINE__, radio->oper_param.operatingClass, radio->oper_param.channel);
    switch (scan_mode) {
    case WIFI_RADIO_SCAN_MODE_ONCHAN: {
        if (chan_num == 0 || chan_list == NULL) {
            chan_num = 1;
            current_channel = radio->oper_param.channel;
        }

        // - allocate space for freq list
        if (RETURN_OK != set_freqs_filter(interface, chan_num, NULL))
            return WIFI_HAL_ERROR;

        // - convert channels to freqs
        for (i = 0; i < chan_num; i++) {
            if (is_ap_mode) {
                // - verify the channel number (it is possible only in AP mode)
                int i_freq;
#if OPTION_GET_CHANNELS_FROM_HOSTAP == 0
                if (current_channel != 0) {
                    i_freq = channel_is_valid_from_radio(radio, current_channel);
                } else {
                    i_freq = channel_is_valid_from_radio(radio, chan_list[i]);
                }
#else
                pthread_mutex_lock(&g_wifi_hal.hapd_lock);
                if (current_channel != 0) {
                    i_freq = channel_is_valid_from_hapd(&interface->u.ap.hapd, current_channel);
                } else {
                    i_freq = channel_is_valid_from_hapd(&interface->u.ap.hapd, chan_list[i]);
                }
                pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
#endif // OPTION_GET_CHANNELS_FROM_HOSTAP
                if (i_freq < 0) {
                    if (current_channel != 0) {
                        wifi_hal_stats_error_print(
                            "%s:%d: [SCAN] channel %u is invalid for radio %d\n", __func__,
                            __LINE__, current_channel, radioIndex);
                    } else {
                        wifi_hal_stats_error_print(
                            "%s:%d: [SCAN] channel %u is invalid for radio %d\n", __func__,
                            __LINE__, chan_list[i], radioIndex);
                    }
                    return WIFI_HAL_ERROR;
                }
                freq = i_freq;
            } else {
                if (current_channel != 0) {
                    if (RETURN_OK !=
                        wifi_channel_to_freq(country, op_class, current_channel, &freq)) {
                        wifi_hal_stats_error_print(
                            "%s:%d: [SCAN] Couldn't get frequency for channel %u\n", __func__,
                            __LINE__, current_channel);
                    }
                } else {
                    if (RETURN_OK != wifi_channel_to_freq(country, op_class, chan_list[i], &freq)) {
                        wifi_hal_stats_error_print(
                            "%s:%d: [SCAN] Couldn't get frequency for channel %u\n", __func__,
                            __LINE__, chan_list[i]);
                        return WIFI_HAL_ERROR;
                    }
                }
            }

            interface->scan_filter.values[i] = freq;
            if (current_channel != 0) {
                wifi_hal_stats_dbg_print("%s:%d: [SCAN] chan:%u -> freq:%u (current channel)\n",
                    __func__, __LINE__, current_channel, freq);
            } else {
                wifi_hal_stats_dbg_print("%s:%d: [SCAN] chan:%u -> freq:%u\n", __func__, __LINE__,
                    chan_list[i], freq);
            }
        }
        break;
    }

    case WIFI_RADIO_SCAN_MODE_OFFCHAN: {
        if (!chan_num || !chan_list) {
            wifi_hal_stats_error_print("%s:%d: [SCAN] OFFCHAN needs chan_num and chan_list param\n",
                __func__, __LINE__);
            return WIFI_HAL_INVALID_ARGUMENTS;
        }

        // - allocate space for freq list
        if (RETURN_OK != set_freqs_filter(interface, chan_num, NULL))
            return WIFI_HAL_ERROR;

        // - convert channels to freqs
        for (i = 0; i < chan_num; i++) {
            if (is_ap_mode) {
                // - verify the channel number (it is possible only in AP mode)
                int i_freq;
#if OPTION_GET_CHANNELS_FROM_HOSTAP == 0
                i_freq = channel_is_valid_from_radio(radio, chan_list[i]);
#else
                pthread_mutex_lock(&g_wifi_hal.hapd_lock);
                i_freq = channel_is_valid_from_hapd(&interface->u.ap.hapd, chan_list[i]);
                pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
#endif // OPTION_GET_CHANNELS_FROM_HOSTAP
                if (i_freq < 0) {
                    wifi_hal_stats_error_print("%s:%d: [SCAN] channel %u is invalid for radio %d\n",
                        __func__, __LINE__, chan_list[i], radioIndex);
                    return WIFI_HAL_ERROR;
                }
                freq = i_freq;
            } else {
                if (RETURN_OK != wifi_channel_to_freq(country, op_class, chan_list[i], &freq)) {
                    wifi_hal_stats_error_print(
                        "%s:%d: [SCAN] Couldn't get frequency for channel %u\n", __func__, __LINE__,
                        chan_list[i]);
                    return WIFI_HAL_ERROR;
                }
            }

            interface->scan_filter.values[i] = freq;
            wifi_hal_stats_dbg_print("%s:%d: [SCAN] chan:%u -> freq:%u\n", __func__, __LINE__,
                chan_list[i], freq);
        }
        break;
    }

    case WIFI_RADIO_SCAN_MODE_FULL: {
        if (!is_ap_mode) {
            wifi_hal_stats_error_print(
                "%s:%d: [SCAN] Full mode is not supported for STA interface\n", __func__, __LINE__);
            return WIFI_HAL_ERROR;
        }

        // - get list of channels (it is possible only in AP mode)
#if OPTION_GET_CHANNELS_FROM_HOSTAP == 0
        if (RETURN_OK != get_valid_freqs_list_from_radio(radio, &interface->scan_filter)) {
            wifi_hal_stats_error_print("%s:%d: [SCAN] Couldn't get the freqs list for radio %d\n",
                __func__, __LINE__, radioIndex);
            return WIFI_HAL_ERROR;
        }
#else
        pthread_mutex_lock(&g_wifi_hal.hapd_lock);
        if (RETURN_OK !=
            get_valid_freqs_list_from_hapd(&interface->u.ap.hapd, &interface->scan_filter)) {
            pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
            wifi_hal_stats_error_print("%s:%d: [SCAN] Couldn't get the freqs list for radio %d\n",
                __func__, __LINE__, radioIndex);
            return WIFI_HAL_ERROR;
        }
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
#endif // OPTION_GET_CHANNELS_FROM_HOSTAP

        for (i = 0; i < interface->scan_filter.num; i++) {
            uint chan = 0;
            wifi_freq_to_channel(interface->scan_filter.values[i], &chan);
            wifi_hal_stats_dbg_print("%s:%d: [SCAN] freq[%u]: %u (channel %u)\n", __func__,
                __LINE__, i, interface->scan_filter.values[i], chan);
        }
        break;
    }

    case WIFI_RADIO_SCAN_MODE_SELECT_CHANNELS: {

        if (chan_num == 0 || chan_list == NULL) {
            wifi_hal_error_print("%s:%d: [SCAN] Needs chan_num and chan_list param\n", __func__,
                __LINE__);
            return WIFI_HAL_INVALID_ARGUMENTS;
        }

        // - allocate space for freq list
        if (RETURN_OK != set_freqs_filter(interface, chan_num, NULL)) {
            wifi_hal_error_print("%s:%d: [SCAN] set_freqs_filter failed\n", __func__, __LINE__);
            return WIFI_HAL_ERROR;
        }

        // - convert channels to freqs
        for (i = 0; i < chan_num; i++) {
            // - verify the channel number (it is possible only in AP mode)
            int i_freq;
#if OPTION_GET_CHANNELS_FROM_HOSTAP == 0
            i_freq = channel_is_valid_from_radio(radio, chan_list[i]);
#else
            pthread_mutex_lock(&g_wifi_hal.hapd_lock);
            i_freq = channel_is_valid_from_hapd(&interface->u.ap.hapd, chan_list[i]);
            pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
#endif // OPTION_GET_CHANNELS_FROM_HOSTAP
            if (i_freq < 0) {
                wifi_hal_error_print("%s:%d: [SCAN] channel %u is invalid for radio %d\n", __func__,
                    __LINE__, chan_list[i], radioIndex);
                return WIFI_HAL_ERROR;
            }
            freq = i_freq;

            interface->scan_filter.values[i] = freq;
            wifi_hal_dbg_print("%s:%d: [SCAN] chan:%u -> freq:%u\n", __func__, __LINE__,
                chan_list[i], freq);
        }
        break;
    }

    default:
        wifi_hal_stats_error_print(
            "%s:%d: [SCAN] scan mode %d is not supported! only supports: "
            "SCAN_MODE_ONCHAN(%d), SCAN_MODE_OFFCHAN(%d) and SCAN_MODE_FULL(%d)\n",
            __func__, __LINE__, scan_mode, WIFI_RADIO_SCAN_MODE_ONCHAN,
            WIFI_RADIO_SCAN_MODE_OFFCHAN, WIFI_RADIO_SCAN_MODE_FULL);
        return WIFI_HAL_ERROR;
    }

    pthread_mutex_lock(&interface->scan_state_mutex);
    interface->scan_state = WIFI_SCAN_STATE_STARTED;
    pthread_mutex_unlock(&interface->scan_state_mutex);

    if (is_ap_mode) {
#if CONFIG_NEIGHBOR_AP_SCAN_ACTIVE
        is_active_scan = true;
        ssid_list[0][0] = '\0'; /* SSID wildcard */
        res = nl80211_start_scan(interface, NL80211_SCAN_FLAG_AP | NL80211_SCAN_FLAG_FLUSH,
            interface->scan_filter.num, interface->scan_filter.values, dwell_time, 1, ssid_list);
#else
        is_active_scan = false;
        res = nl80211_start_scan(interface, NL80211_SCAN_FLAG_AP | NL80211_SCAN_FLAG_FLUSH,
            interface->scan_filter.num, interface->scan_filter.values, dwell_time, 0, NULL);
#endif
    } else {
        is_active_scan = true;
        wifi_strcpy(ssid_list[0], sizeof(ssid_list[0]), interface->vap_info.u.sta_info.ssid);
        res = nl80211_start_scan(interface, 0, interface->scan_filter.num,
            interface->scan_filter.values, dwell_time, 1, ssid_list);
    }

    if (res) {
        pthread_mutex_lock(&interface->scan_state_mutex);
        interface->scan_state = WIFI_SCAN_STATE_NONE;
        pthread_mutex_unlock(&interface->scan_state_mutex);
        wifi_hal_stats_error_print("%s:%d: [SCAN] scan trigger failed for '%s'\n", __func__,
            __LINE__, interface->name);
        return WIFI_HAL_ERROR;
    }

    wifi_hal_stats_dbg_print("%s:%d: [SCAN] scan triggered (%s, %s)\n", __func__, __LINE__,
        (is_ap_mode ? "AP" : "STA"), (is_active_scan ? "ACTIVE" : "PASSIVE"));
    return WIFI_HAL_SUCCESS;
}

/* --- copied from platform/banana-pi/platform.c:560 --- */
extern "C" int wifi_startNeighborScan(INT apIndex, wifi_neighborScanMode_t scan_mode, INT dwell_time, UINT chan_num, UINT *chan_list)
{
    return wifi_hal_startNeighborScan(apIndex, scan_mode, dwell_time, chan_num, chan_list);
}
