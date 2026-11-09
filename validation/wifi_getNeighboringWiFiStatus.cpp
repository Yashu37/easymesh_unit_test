/*
 * HANDLER: wifi_getNeighboringWiFiStatus
 *
 * Functions copied VERBATIM from rdk-wifi-hal (~/Desktop/G/rdk-wifi-hal): the banana-pi forwarder wifi_getNeighboringWiFiStatus
 * (platform/banana-pi/platform.c:565), which only calls wifi_hal_getNeighboringWiFiStatus (src/wifi_hal.c:3691) -> _wifi_hal_getNeighboringWiFiStatus
 * (3587), plus what it uses: copy_scan_results (3078), scan_result_passes_filter (3057), decode_bss_info_to_neighbor_ap_info (2862) and the
 * string helpers of src/wifi_hal_nl80211_utils.c (wifi_strcpy, wifi_strcat, str_list_append, wifi_enum_bitmap_to_str,
 * wifi_ieee80211Variant_to_str, wifi_channelBandwidth_to_str, wifi_bitrate_to_str and their maps).  OPTION_GET_CHANNELS_FROM_HOSTAP == 1 as in
 * wifi_startNeighborScan.  There is no fix switch: no fix is applied here.
 *
 * Scaffolding only: reduced interface / radio structures (hwr_gnw.h), a stand-in hash map (count / get_first / get_next over an array),
 * runner-controlled get_radio_by_rdk_index / get_private_vap_interface, a calloc / realloc that the runner can make fail,
 * wifi_freq_to_channel over the hostap channel ranges (2412-2472, 2484, 5000-5895, 5955-7115), and the *_print macros mapped to the log sink.
 */
#include "hwr_gnw.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#define wifi_hal_stats_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_stats_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)        hwr_print(1, format, ##__VA_ARGS__)
#define wifi_interface_info_t   gnw_interface_t
#define wifi_radio_info_t       gnw_radio_t
#define OPTION_GET_CHANNELS_FROM_HOSTAP 1
#define CONFIG_IEEE80211BE 1
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#ifndef MACSTR
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#endif
#define WLAN_CAPABILITY_ESS  (1 << 0)
#define WLAN_CAPABILITY_IBSS (1 << 1)
#define wifi_getNeighboringWiFiStatus      hwr_wifi_getNeighboringWiFiStatus
#define wifi_hal_getNeighboringWiFiStatus  hwr_wifi_hal_getNeighboringWiFiStatus
typedef unsigned int uint;
/* src/wifi_hal_priv.h:301-305 verbatim */
typedef struct wifi_enum_to_str_map
{
    int enum_val;
    const char *str_val;
} wifi_enum_to_str_map_t;
/* src/wifi_hal_priv.h:447-458 */
enum { WIFI_SCAN_STATE_NONE, WIFI_SCAN_STATE_ERROR, WIFI_SCAN_STATE_STARTED, WIFI_SCAN_STATE_ABORTED };
#define WIFI_SCAN_RES_COLLECTED_API   0x01  // - scan results are available for API call
#define WIFI_SCAN_RES_COLLECTED_TEST  0x02  // - scan results are available only for test purposes

/* src/wifi_hal.c:62-92 (not CONFIG_WIFI_EMULATOR) */
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

gnw_world_t hwr_gnw_world;

static gnw_radio_t *get_radio_by_rdk_index(unsigned int index)
{
    return (hwr_gnw_world.radio && hwr_gnw_world.radio_index == index) ? hwr_gnw_world.radio : NULL;
}
static gnw_interface_t *get_private_vap_interface(gnw_radio_t *radio)
{
    (void)radio;
    return hwr_gnw_world.priv_iface;
}

/* hash map stand-in (collection.c): hash_map_count(NULL) dereferences NULL exactly like the real one */
static uint32_t hash_map_count(gnw_map_t *map) { return (uint32_t)map->n; }
static void *hash_map_get_first(gnw_map_t *map) { return map->n ? map->items[0] : NULL; }
static void *hash_map_get_next(gnw_map_t *map, void *cur)
{
    for (int i = 0; i < map->n; i++) if (map->items[i] == cur) return (i + 1 < map->n) ? map->items[i + 1] : NULL;
    return NULL;
}

/* allocation the runner can make fail */
static void *gnw_calloc(size_t n, size_t s)  { hwr_gnw_world.calloc_calls++;  return hwr_gnw_world.fail_calloc  ? NULL : calloc(n, s); }
static void *gnw_realloc(void *p, size_t s)  { hwr_gnw_world.realloc_calls++; return hwr_gnw_world.fail_realloc ? NULL : realloc(p, s); }
#define calloc  gnw_calloc
#define realloc gnw_realloc

/* wifi_hal_nl80211_utils.c:4833 over hostap ieee80211_freq_to_chan() ranges */
static int wifi_freq_to_channel(int freq, uint *channel)
{
    *channel = 0;
    if (freq >= 2412 && freq <= 2472 && ((freq - 2407) % 5) == 0) *channel = (freq - 2407) / 5;
    else if (freq == 2484) *channel = 14;
    else if (freq >= 5000 && freq <= 5895 && (freq % 5) == 0) *channel = (freq - 5000) / 5;
    else if (freq >= 5955 && freq <= 7115 && ((freq - 5950) % 5) == 0) *channel = (freq - 5950) / 5;
    else return RETURN_ERR;
    return RETURN_OK;
}

/* --- copied from src/wifi_hal_nl80211_utils.c:1806-1849 --- */
static const wifi_enum_to_str_map_t wifi_variant_Map[] =
{
    {WIFI_80211_VARIANT_A,  "a"},
    {WIFI_80211_VARIANT_B,  "b"},
    {WIFI_80211_VARIANT_G,  "g"},
    {WIFI_80211_VARIANT_N,  "n"},
    {WIFI_80211_VARIANT_AC, "ac"},
    {WIFI_80211_VARIANT_AD, "ad"},
    {WIFI_80211_VARIANT_AX, "ax"},
#ifdef CONFIG_IEEE80211BE
    {WIFI_80211_VARIANT_BE, "be"},
#endif /* CONFIG_IEEE80211BE */
};

static const wifi_enum_to_str_map_t wifi_bandwidth_Map[] =
{
    {WIFI_CHANNELBANDWIDTH_20MHZ,    "20MHz" },
    {WIFI_CHANNELBANDWIDTH_40MHZ,    "40MHz" },
    {WIFI_CHANNELBANDWIDTH_80MHZ,    "80MHz" },
    {WIFI_CHANNELBANDWIDTH_160MHZ,   "160MHz" },
    {WIFI_CHANNELBANDWIDTH_80_80MHZ, "80+80MHz" },
#ifdef CONFIG_IEEE80211BE
    {WIFI_CHANNELBANDWIDTH_320MHZ,   "320MHz" },
#endif /* CONFIG_IEEE80211BE */
};

// Map of bitrate enum to string in Mbps format
static const wifi_enum_to_str_map_t wifi_bitrate_Map[] =
{
    {WIFI_BITRATE_DEFAULT, "default" },
    {WIFI_BITRATE_1MBPS,   "1Mbps"     },
    {WIFI_BITRATE_2MBPS,   "2Mbps"     },
    {WIFI_BITRATE_5_5MBPS, "5.5Mbps"     },
    {WIFI_BITRATE_6MBPS,   "6Mbps"     },
    {WIFI_BITRATE_9MBPS,   "9Mbps"     },
    {WIFI_BITRATE_11MBPS,  "11Mbps"    },
    {WIFI_BITRATE_12MBPS,  "12Mbps"    },
    {WIFI_BITRATE_18MBPS,  "18Mbps"    },
    {WIFI_BITRATE_24MBPS,  "24Mbps"    },
    {WIFI_BITRATE_36MBPS,  "36Mbps"    },
    {WIFI_BITRATE_48MBPS,  "48Mbps"    },
    {WIFI_BITRATE_54MBPS,  "54Mbps"    },
};


/* --- copied from src/wifi_hal_nl80211_utils.c:4954-5148 (wifi_strcpy ... wifi_bitrate_to_str) --- */
int wifi_strcpy(char *dest, size_t dest_size, const char *src)
{
    size_t srclen;

    if (dest == NULL || src == NULL || dest_size == 0)
        return -1;

    dest[0] = '\0';
    srclen = strnlen(src, dest_size);
    if (srclen >= dest_size)
        return -1;

    // Check for overlap
    if ((src >= dest && src < dest + dest_size) ||
        (dest >= src && dest < src + srclen))
        return -1;

    memcpy(dest, src, srclen);
    dest[srclen] = '\0';
    return 0;
}

int wifi_strcat(char *dest, size_t dest_size, const char *src)
{
    size_t destlen, srclen;

    if (dest == NULL || src == NULL || dest_size == 0)
        return -1;

    destlen = strnlen(dest, dest_size);
    srclen = strnlen(src, dest_size);

    if (destlen + srclen >= dest_size)
        return -1;

    // Check for overlap
    if ((src >= dest && src < dest + dest_size) ||
        (dest >= src && dest < src + srclen))
        return -1;

    memcpy(dest + destlen, src, srclen);
    dest[destlen + srclen] = '\0';
    return 0;
}

int str_list_append(char *dest, size_t dest_size, const char *src)
{
    if (dest_size == 0) return 0;
    if (dest[0] == '\0') {
        if (wifi_strcpy(dest, dest_size, src)) return -1;
    } else {
        if (wifi_strcat(dest, dest_size, ",")) return -1;
        if (wifi_strcat(dest, dest_size, src)) return -1;
    }
    return 0;
}

static int wifi_enum_bitmap_to_str(char *dest, size_t dest_size,
    const wifi_enum_to_str_map_t map[], size_t map_size, const char *prefix,
    int bitmap)
{
    size_t i;

    if ((dest == NULL) || (dest_size == 0)) {
        wifi_hal_error_print("%s:%d: NULL or zero-size buffer\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    *dest = '\0';
    for (i = 0; i < map_size; ++i) {
        if (bitmap & map[i].enum_val) {
            if (str_list_append(dest, dest_size, prefix))
                goto fail;
            if (wifi_strcat(dest, dest_size, map[i].str_val))
                goto fail;
        }
    }
    return RETURN_OK;

fail:
    wifi_hal_error_print("%s:%d: cannot to append a new value to the string buffer\n", __func__, __LINE__);
    return RETURN_ERR;
}

int wifi_ieee80211Variant_to_str(char *dest, size_t dest_size, wifi_ieee80211Variant_t variant,
    const char *str)
{
    const char *mode;

    if (*str != '\0') {
        return wifi_enum_bitmap_to_str(dest, dest_size, wifi_variant_Map,
            ARRAY_SIZE(wifi_variant_Map), str, (int)variant);
    } else {
        if ((dest != NULL) && (dest_size != 0)) {
            *dest = '\0';

            if (variant & WIFI_80211_VARIANT_A) {
                mode = "a";
                str_list_append(dest, dest_size, mode);
            }
            if (variant & WIFI_80211_VARIANT_B) {
                mode = "b";
                str_list_append(dest, dest_size, mode);
            }
            if (variant & WIFI_80211_VARIANT_G) {
                mode = "g";
                str_list_append(dest, dest_size, mode);
            }
            if (variant &
                (WIFI_80211_VARIANT_N | WIFI_80211_VARIANT_AC | WIFI_80211_VARIANT_AX |
                    WIFI_80211_VARIANT_BE)) {
                if ((variant & WIFI_80211_VARIANT_BE) && (variant & WIFI_80211_VARIANT_AX)) {
                    // Wi-Fi 7 supports both AX (6E base) and BE (Wi-Fi 7)
                    str_list_append(dest, dest_size, "ax");
                    str_list_append(dest, dest_size, "be");
                } else {
                    if (variant & WIFI_80211_VARIANT_BE) {
                        mode = "be";
                    } else if (variant & WIFI_80211_VARIANT_AX) {
                        mode = "ax";
                    } else if (variant & WIFI_80211_VARIANT_AC) {
                        mode = "ac";
                    } else {
                        mode = "n";
                    }
                    str_list_append(dest, dest_size, mode);
                }
            }
        } else {
            wifi_hal_error_print("%s:%d: NULL or zero-size buffer\n", __func__, __LINE__);
            return RETURN_ERR;
        }
    }

    return RETURN_OK;
}

int wifi_channelBandwidth_to_str(char *dest, size_t dest_size, wifi_channelBandwidth_t bandwidth)
{
    return wifi_enum_bitmap_to_str(dest, dest_size,
        wifi_bandwidth_Map, ARRAY_SIZE(wifi_bandwidth_Map),
        "", (int)bandwidth);
}

int wifi_bitrate_to_str(char *dest, size_t dest_size, wifi_bitrate_t bitrate)
{
    return wifi_enum_bitmap_to_str(dest, dest_size,
        wifi_bitrate_Map, ARRAY_SIZE(wifi_bitrate_Map),
        "", (int)bitrate);
}

/* --- copied from src/wifi_hal.c:2840-3055 (macros + decode_bss_info_to_neighbor_ap_info) --- */
// - helper macro for copying string
#define _COPY(out,s) ({ \
    int res = wifi_strcpy(out, sizeof(out), s); \
    if (res) wifi_hal_stats_error_print("%s:%d: string copying error!\n", __func__, __LINE__); \
    res; \
})

// - helper macro for adding string to a comma-separated list
#define _APPEND(out,s) ({ \
    int res = str_list_append(out, sizeof(out), s); \
    if (res) wifi_hal_stats_error_print("%s:%d: string adding error!\n", __func__, __LINE__); \
    res; \
})

// - helper macro for string formatting
#define _FORMAT(out, fmt, args...) ({ \
    int res = snprintf(out, sizeof(out), fmt, ##args); \
    res = ((res < 0) || (res >= sizeof(out))); \
    if (res) wifi_hal_stats_error_print("%s:%d: string format error!\n", __func__, __LINE__); \
    res; \
})

static int decode_bss_info_to_neighbor_ap_info(wifi_neighbor_ap2_t *ap, const wifi_bss_info_t *bss)
{
    int ret = RETURN_OK;
    const char *str;

    memset(ap, 0, sizeof(*ap));

    /*  This function check each step, but do not stop filling the output if one step fails.
        This allows to see the rest of the information even if one step fails.
     */

    // - ap_SSID
    if (_COPY(ap->ap_SSID, bss->ssid)) {
        ret = RETURN_ERR;
    }

    // - ap_BSSID
    if (_FORMAT(ap->ap_BSSID, MACSTR, MAC2STR(bss->bssid))) {
        ret = RETURN_ERR;
    }

    // - ap_Mode
    str = "";
    if (bss->caps & WLAN_CAPABILITY_ESS)
        str = "Infrastructure";
    if (bss->caps & WLAN_CAPABILITY_IBSS)
        str = "AdHoc";

    if (_COPY(ap->ap_Mode, str)) {
        ret = RETURN_ERR;
    }

    // - ap_Channel
    if (RETURN_OK != wifi_freq_to_channel(bss->freq, &ap->ap_Channel)) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] Cannot convert freq %u to the channel number!\n",  __func__, __LINE__, bss->freq);
        ret = RETURN_ERR;
    }

    // - ap_SignalStrength
    ap->ap_SignalStrength = bss->rssi;

    // -ap_freq
    ap->ap_freq = bss->freq;

    // - ap_SecurityModeEnabled
    switch (bss->sec_mode) {
        case wifi_security_mode_none:
            str = "None";
            break;
        case wifi_security_mode_wep_64:
        case wifi_security_mode_wep_128:
            str = "WEP";
            break;
        case wifi_security_mode_wpa_personal:
            str = "WPA-Personal";
            break;
        case wifi_security_mode_wpa_enterprise:
            str = "WPA-Enterprise";
            break;
        case wifi_security_mode_wpa2_personal:
            str = "WPA2-Personal";
            break;
        case wifi_security_mode_wpa2_enterprise:
            str = "WPA2-Enterprise";
            break;
        case wifi_security_mode_wpa_wpa2_personal:
            str = "WPA-WPA2-Personal";
            break;
        case wifi_security_mode_wpa_wpa2_enterprise:
            str = "WPA-WPA2-Enterprise";
            break;
        /* For future usage */
        case wifi_security_mode_wpa3_personal:
            str = "WPA3-Personal";
            break;
        case wifi_security_mode_wpa3_transition:
            if (bss->oper_freq_band == WIFI_FREQUENCY_6_BAND || bss->oper_freq_band == WIFI_FREQUENCY_60_BAND) {
                str = "WPA3-Personal";
            } else {
                str = "WPA3-Personal-Transition";
            }
            break;
        case wifi_security_mode_wpa3_enterprise:
            str = "WPA3-Enterprise";
            break;
        case wifi_security_mode_wpa3_compatibility:
            str = "WPA3-Compatibility";
            break;
        default:
            str = "?";
    }
    if (_COPY(ap->ap_SecurityModeEnabled, str)) {
        ret = RETURN_ERR;
    }

    // - ap_EncryptionMode
    switch (bss->enc_method) {
        case wifi_encryption_tkip:
            str = "TKIP";
            break;
        case wifi_encryption_aes:
            str = "AES";
            break;
        case wifi_encryption_aes_tkip:
            str = "AES+TKIP";
            break;
        default:
            str = "None";
            break;
    }
    if (_COPY(ap->ap_EncryptionMode, str)) {
        ret = RETURN_ERR;
    }

    // - ap_OperatingFrequencyBand
    switch (bss->oper_freq_band) {
        case WIFI_FREQUENCY_2_4_BAND:
            str = "2.4GHz";
            break;
        case WIFI_FREQUENCY_5_BAND:
        case WIFI_FREQUENCY_5L_BAND:
        case WIFI_FREQUENCY_5H_BAND:
            str = "5GHz";
            break;
        case WIFI_FREQUENCY_6_BAND:
        case WIFI_FREQUENCY_60_BAND:
            str = "6GHz";
            break;
        default:
            str = "";
            break;
    }
    if (_COPY(ap->ap_OperatingFrequencyBand, str)) {
        ret = RETURN_ERR;
    }

    // - ap_SupportedStandards
    // 4th argument - Any prefix to be added before the standard i.e., 802.11
    if (wifi_ieee80211Variant_to_str(ap->ap_SupportedStandards, sizeof(ap->ap_SupportedStandards),
            bss->supp_standards, "")) {
        ret = RETURN_ERR;
    }

    // - ap_OperatingStandards
    if (wifi_ieee80211Variant_to_str(ap->ap_OperatingStandards, sizeof(ap->ap_OperatingStandards),
            bss->oper_standards, "")) {
        ret = RETURN_ERR;
    }

    // - ap_OperatingChannelBandwidth
    if (wifi_channelBandwidth_to_str(ap->ap_OperatingChannelBandwidth, sizeof(ap->ap_OperatingChannelBandwidth), bss->oper_chan_bw)) {
        ret = RETURN_ERR;
    }

    // - ap_BeaconPeriod
    ap->ap_BeaconPeriod = bss->beacon_int;
    // - ap_Noise
    ap->ap_Noise = bss->noise;

    // - ap_BasicDataTransferRates
    if (wifi_bitrate_to_str(ap->ap_BasicDataTransferRates, sizeof(ap->ap_BasicDataTransferRates), bss->basic_rates)) {
        ret = RETURN_ERR;
    }

    // - ap_SupportedDataTransferRates
    if (wifi_bitrate_to_str(ap->ap_SupportedDataTransferRates, sizeof(ap->ap_SupportedDataTransferRates), bss->supp_rates)) {
        ret = RETURN_ERR;
    }

    // - ap_DTIMPeriod
    ap->ap_DTIMPeriod = bss->dtim_period;
  
    /*
     * Channel Utilization (CU) may be derived from multiple sources (e.g., BSS Load IE
     * or other scan attributes like NL80211_BSS_CU). Populate ap_ChannelUtilization
     * unconditionally to preserve legacy behavior and avoid dropping valid CU when
     * the BSS Load IE is absent.
     *
     * Only BSS Load specific fields (bss_load_element_present, ap_StaCount) are gated
     * on the presence of the BSS Load IE.
     */
    ap->ap_ChannelUtilization = bss->chan_utilization;

    // - bss_load_element 
    if (bss->bss_load_element_present) {
        ap->bss_load_element_present = bss->bss_load_element_present;
        ap->ap_StaCount = bss->station_cnt;
    }

    wifi_hal_stats_dbg_print("%s:%d: [SCAN] bssid: %s, ssid: %s, channel: %d, noise: %d station_cnt %u\n",
        __func__, __LINE__, ap->ap_BSSID, ap->ap_SSID, ap->ap_Channel, ap->ap_Noise, ap->ap_StaCount);

    return ret;
}

/* --- copied from src/wifi_hal.c:3057-3145 (scan_result_passes_filter, copy_scan_results) --- */
static bool scan_result_passes_filter(wifi_interface_info_t *interface, uint freq)
{
    uint *freqs = interface->scan_filter.values;
    uint num_freqs = interface->scan_filter.num;
    uint i;

    if (freqs == NULL || num_freqs == 0) {
        /* filter is empty, allow this result */
        return true;
    }

    for (i = 0; (i < num_freqs) && (freqs[i] > 0); i++) {
        if (freq == freqs[i]) {
            return true;
        }
    }

    /* not in scan request, filter this result */
    return false;
}

static int copy_scan_results(wifi_interface_info_t *interface, wifi_neighbor_ap2_t **ap_array, uint *array_size)
{
    uint results_copied = 0;
    int ret = RETURN_ERR;

    uint out_size = 0;
    wifi_neighbor_ap2_t* out_array = NULL;
    wifi_bss_info_t *scan_info_ap;

    // mutex_lock ?? (already done by caller)

    *ap_array = NULL;
    *array_size = 0;

    out_size = hash_map_count(interface->scan_info_ap_map[1]);
    if (out_size == 0) {
        ret = RETURN_OK;
        goto exit;
    }

    out_array = (wifi_neighbor_ap2_t *)calloc(out_size, sizeof(wifi_neighbor_ap2_t));
    if (out_array == NULL) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] memory allocation error!\n", __func__, __LINE__);
        goto exit;
    }

    scan_info_ap = (wifi_bss_info_t*)hash_map_get_first(interface->scan_info_ap_map[1]);
    while (scan_info_ap != NULL) {
        if (scan_result_passes_filter(interface, scan_info_ap->freq)) {
            if (RETURN_OK != decode_bss_info_to_neighbor_ap_info(&out_array[results_copied], scan_info_ap)) {
                wifi_hal_stats_error_print("%s:%d: [SCAN] bss info decoding error! "
                    "Some fields in AP struct may contain incorrect data\n", __func__, __LINE__);
            }
            results_copied++;
        }
        else {
            wifi_hal_stats_dbg_print("%s:%d: [SCAN] scan result %s, %u Mhz was dropped\n", __func__, __LINE__,
                scan_info_ap->ssid, scan_info_ap->freq);
        }
        scan_info_ap = (wifi_bss_info_t*)hash_map_get_next(interface->scan_info_ap_map[1], scan_info_ap);
    }

    wifi_hal_stats_dbg_print("%s:%d: [SCAN] out_size:%u, copied:%u\n", __func__, __LINE__, out_size, results_copied);
    if (results_copied == 0) {
        wifi_hal_stats_dbg_print("%s:%d: [SCAN] All results were filtered out\n", __func__, __LINE__);
        free(out_array);
        out_array = NULL;
        out_size = 0;
    }
    else if (results_copied < out_size) {
        wifi_neighbor_ap2_t *new_out_array = (wifi_neighbor_ap2_t *)realloc(out_array, sizeof(wifi_neighbor_ap2_t) * results_copied);
        if (new_out_array == NULL) {
            // - error, but not critical, original array still is valid
            wifi_hal_stats_error_print("%s:%d: [SCAN] memory re-allocation error!\n", __func__, __LINE__);
        }
        else
            out_array = new_out_array;
        out_size = results_copied;
    }

    *ap_array = out_array;
    *array_size = out_size;
    ret = RETURN_OK;

exit:
    // mutex_unlock ??
    return ret;
}

/* --- copied from src/wifi_hal.c:3587-3694 (_wifi_hal_getNeighboringWiFiStatus + wifi_hal_getNeighboringWiFiStatus) --- */
static INT _wifi_hal_getNeighboringWiFiStatus(INT radioIndex, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *output_array_size, bool test_mode)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
    int ret;

    wifi_hal_stats_dbg_print("%s:%d: [SCAN] == ENTER ==\n", __func__, __LINE__);

    if (!neighbor_ap_array || !output_array_size) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] Invalid parameters\n", __func__, __LINE__);
        return WIFI_HAL_INVALID_ARGUMENTS;
    }

    RADIO_INDEX_ASSERT(radioIndex);

    radio = get_radio_by_rdk_index(radioIndex);
    if (radio == NULL) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] radio for radio index:%d not found\n", __func__, __LINE__, radioIndex);
        return WIFI_HAL_ERROR;
    }

#if OPTION_GET_CHANNELS_FROM_HOSTAP == 0
    interface = get_primary_interface(radio);
    if (interface == NULL) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] primary interface for radio '%s' not found\n", __func__, __LINE__, radio->name);
        return WIFI_HAL_ERROR;
    }
#else
    interface = get_private_vap_interface(radio);
    if (interface == NULL) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] private interface for radio '%s' not found\n", __func__, __LINE__, radio->name);
        return WIFI_HAL_ERROR;
    }
#endif

    pthread_mutex_lock(&interface->scan_state_mutex);

    if (interface->scan_state == WIFI_SCAN_STATE_ABORTED) {
        interface->scan_state = WIFI_SCAN_STATE_NONE;
        pthread_mutex_unlock(&interface->scan_state_mutex);
        wifi_hal_stats_error_print("%s:%d: [SCAN] Scan was aborted\n", __func__, __LINE__);
        return WIFI_HAL_ERROR;
    }

    if (interface->scan_state == WIFI_SCAN_STATE_ERROR) {
        interface->scan_state = WIFI_SCAN_STATE_NONE;
        pthread_mutex_unlock(&interface->scan_state_mutex);
        wifi_hal_stats_error_print("%s:%d: [SCAN] Error happened during scan\n", __func__, __LINE__);
        return WIFI_HAL_ERROR;
    }

    /* If API scan results are available, return them regardless of scan_state */
    if (interface->scan_has_results & WIFI_SCAN_RES_COLLECTED_API)
        goto get_results;

    /* In test mode: If TEST scan results are available, return them regardless of scan_state */
    if (test_mode && (interface->scan_has_results & WIFI_SCAN_RES_COLLECTED_TEST))
        goto get_results;

    if (interface->scan_state == WIFI_SCAN_STATE_NONE) {
        pthread_mutex_unlock(&interface->scan_state_mutex);
        wifi_hal_stats_dbg_print("%s:%d: [SCAN] Scan was not triggered\n", __func__, __LINE__);
        return WIFI_HAL_ERROR;
    }

    if (interface->scan_state == WIFI_SCAN_STATE_STARTED) {
        pthread_mutex_unlock(&interface->scan_state_mutex);
        wifi_hal_stats_dbg_print("%s:%d: [SCAN] Scan is running, come later\n", __func__, __LINE__);
        errno = EAGAIN;
        return WIFI_HAL_NOT_READY;
    }

get_results:
    if (interface->scan_state == WIFI_SCAN_STATE_STARTED)
        wifi_hal_stats_dbg_print("%s:%d: [SCAN] Scan is running, but previous scan results are available\n", __func__, __LINE__);
    else
        wifi_hal_stats_dbg_print("%s:%d: [SCAN] Scan results are available\n", __func__, __LINE__);

    pthread_mutex_lock(&interface->scan_info_ap_mutex);
    ret = copy_scan_results(interface, neighbor_ap_array, output_array_size);
    pthread_mutex_unlock(&interface->scan_info_ap_mutex);
    if (ret != RETURN_OK) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] copy_scan_results returned with error\n", __func__, __LINE__);
    }

    if (test_mode) {
        // - test mode: reset results only if scan is in progress;
        if (interface->scan_state == WIFI_SCAN_STATE_STARTED)
            interface->scan_has_results &= ~WIFI_SCAN_RES_COLLECTED_TEST;
    }
    else {
        // - reset results for normal API call
        interface->scan_has_results &= ~WIFI_SCAN_RES_COLLECTED_API;
    }

    pthread_mutex_unlock(&interface->scan_state_mutex);

    if (ret != RETURN_OK)
        return WIFI_HAL_ERROR;

    wifi_hal_stats_dbg_print("%s:%d: [SCAN] SCAN results are ready | output_array_size:%d\n", __func__, __LINE__, *output_array_size);
    return WIFI_HAL_SUCCESS;
}

extern "C" INT wifi_hal_getNeighboringWiFiStatus(INT radioIndex, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *output_array_size)
{
    return _wifi_hal_getNeighboringWiFiStatus(radioIndex, neighbor_ap_array, output_array_size, false);
}

/* --- platform.c:565 --- */
extern "C" {
int wifi_getNeighboringWiFiStatus(INT radio_index, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *output_array_size)
{
    return wifi_hal_getNeighboringWiFiStatus(radio_index, neighbor_ap_array, output_array_size);
}
}
