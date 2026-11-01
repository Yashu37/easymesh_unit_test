/*
 * HANDLER: device_statistics_info
 *
 * Function copied VERBATIM from OneWifi source/apps/analytics/wifi_analytics.c.
 * No fixes. Local arrays and their writers:
 *   - tm_str[128]        <- get_formatted_time(tm_str)   (snprintf(time, 128))
 *   - temp_str[128]      <- snprintf(temp_str, sizeof(temp_str), ...) x3
 *   - sta_stats_str[256] <- snprintf(sta_stats_str, sizeof(sta_stats_str), ...)
 *   - client_mac[32]     <- to_mac_str(sta_mac, client_mac)  (snprintf(key, 18))
 *
 * Redirects (write into runner slots of the SAME size, then copy back):
 *   - get_formatted_time() -> ds_get_formatted_time(): verbatim
 *     get_formatted_time (source/utils/wifi_util.c) on ds_slot_tm (128).
 *   - to_mac_str() -> ds_to_mac_str(): verbatim to_mac_str on ds_slot_mac (32).
 *   - snprintf() -> ds_snprintf(): real vsnprintf on ds_slot_128 (temp_str)
 *     or ds_slot_256 (sta_stats_str), picked by the size argument.
 * The RUNNER poisons each slot past its size (128 / 32 / 128 / 256), so a
 * write past the real array size aborts. The arrays themselves are also
 * guarded by ASan stack redzones.
 *
 * Scaffolding (NOT the function under test):
 *   - wifi_util_info_print: really formats its arguments (vsnprintf to
 *     scratch), so temp_str / sta_stats_str / radio bw are read.
 *   - getNumberRadios / get_dev_stats_for_radio / get_stats_for_sta /
 *     hash_map_get_first / hash_map_get_next: stubs over runner data.
 *   - getrusage: real.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "common.h"

/* --- scaffolding --- */
#define RETURN_OK 0
#define WIFI_ANALYTICS 0
#define analytics_format_mgr_core    "MGR -> CORE : %s : %s\r\n"     /* wifi_analytics.h */
#define analytics_format_generic     "%s -> %s : %s : %s\r\n"
#define analytics_format_hal_core    "HAL -> CORE : %s : %s\r\n"

static void wifi_util_info_print(int module, const char *fmt, ...)
{
    char scratch[4096];
    va_list ap; (void)module;
    va_start(ap, fmt);
    vsnprintf(scratch, sizeof(scratch), fmt, ap);
    va_end(ap);
}

static unsigned int getNumberRadios(void) { return (unsigned int)ds_num_radios; }
static int get_dev_stats_for_radio(unsigned int radio_index, radio_data_t *radio_stats)
{
    if (radio_index == (unsigned int)ds_radio_fail_idx) return -1;
    radio_stats->primary_radio_channel = 36 + radio_index * 4;
    memcpy(radio_stats->channel_bandwidth, ds_bw, sizeof(radio_stats->channel_bandwidth));
    radio_stats->NoiseFloor = -95;
    radio_stats->channelUtil = 42;
    radio_stats->channelInterference = 7;
    ds_radio_calls++;
    return RETURN_OK;
}
static void *get_stats_for_sta(unsigned int ap_index, mac_address_t mac)
{
    (void)mac;
    if (ap_index == DS_NO_STATS_AP) return NULL;
    return &ds_sta_data[ap_index % DS_MAX_STA];
}
static void *hash_map_get_first_ds(void *map)
{
    (void)map; ds_iter = 0;
    return ds_nsta ? (void *)ds_sta_pool[0] : NULL;
}
static void *hash_map_get_next_ds(void *map, void *cur)
{
    (void)map; (void)cur;
    ds_iter++;
    return ds_iter < ds_nsta ? (void *)ds_sta_pool[ds_iter] : NULL;
}

/* verbatim from source/utils/wifi_util.c */
static char *get_formatted_time(char *time)
{
    struct tm *tm_info;
    struct timeval tv_now;
    char tmp[128];

    gettimeofday(&tv_now, NULL);
    tm_info = (struct tm *)localtime(&tv_now.tv_sec);

    strftime(tmp, 128, "%y%m%d-%T", tm_info);

    snprintf(time, 128, "%s.%06lld", tmp, (long long)tv_now.tv_usec);
    return time;
}

/* verbatim from source/utils/wifi_util.c */
static char *to_mac_str(mac_address_t mac, mac_addr_str_t key)
{
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return (char *)key;
}

/* redirects: write into runner slots of the same size as the real array */
static char *ds_get_formatted_time(char *t)
{
    memset(ds_slot_tm, 0, DS_TM_SZ);
    get_formatted_time(ds_slot_tm);
    memcpy(t, ds_slot_tm, DS_TM_SZ);
    ds_tm_len = strnlen(ds_slot_tm, DS_TM_SZ);
    return t;
}
static char *ds_to_mac_str(mac_address_t mac, char *key)
{
    memset(ds_slot_mac, 0, DS_MAC_SZ);
    to_mac_str(mac, ds_slot_mac);
    memcpy(key, ds_slot_mac, DS_MAC_SZ);
    ds_mac_len = strnlen(ds_slot_mac, DS_MAC_SZ);
    return key;
}
static int ds_snprintf(char *out, size_t sz, const char *fmt, ...)
{
    int r;
    va_list ap;
    char *slot = (sz == DS_STA_SZ) ? ds_slot_256 : ds_slot_128;
    size_t cap = (sz == DS_STA_SZ) ? DS_STA_SZ : DS_TMP_SZ;
    if (sz > cap) sz = cap;
    memset(slot, 0, sz);
    va_start(ap, fmt);
    r = vsnprintf(slot, sz, fmt, ap);
    va_end(ap);
    memcpy(out, slot, sz);
    {   /* record the LONGEST string written into each array */
        size_t l = strnlen(slot, sz);
        if (slot == ds_slot_256) { if (l > ds_sta_len) ds_sta_len = l; }
        else if (l > ds_tmp_len) ds_tmp_len = l;
    }
    return r;
}
#define get_formatted_time(t)      ds_get_formatted_time(t)
#define to_mac_str(m, k)           ds_to_mac_str((m), (k))
#define snprintf(o, n, ...)        ds_snprintf((o), (n), __VA_ARGS__)
#define hash_map_get_first(m)      hash_map_get_first_ds(m)
#define hash_map_get_next(m, d)    hash_map_get_next_ds((m), (d))

/* --- copied verbatim from source/apps/analytics/wifi_analytics.c --- */
void device_statistics_info(analytics_data_t *data)
{
    hash_map_t   *sta_map;
    char         temp_str[128];
    unsigned int radio_index = 0;
    radio_data_t radio_stats;
    char   client_mac[32], sta_stats_str[256], tm_str[128];
    analytics_sta_info_t    *sta_info;
    wifi_associated_dev3_t  *dev_stats;
    sta_data_t *sta_data;
    struct rusage usage;
    float user, system;

    getrusage(RUSAGE_SELF, &usage);

    user = (usage.ru_utime.tv_sec - data->last_usage.ru_utime.tv_sec) +
                               1e-6*(usage.ru_utime.tv_usec - data->last_usage.ru_utime.tv_usec);
    system = (usage.ru_stime.tv_sec - data->last_usage.ru_stime.tv_sec) +
                               1e-6*(usage.ru_stime.tv_usec - data->last_usage.ru_stime.tv_usec);

    if ((data->minutes_alive % 60) == 0) {
        // print time of day every hour
        get_formatted_time(tm_str);
        snprintf(temp_str, sizeof(temp_str), "utc:%s user:%f system:%f", tm_str, user, system);
    } else {
        snprintf(temp_str, sizeof(temp_str), "minutes:%u user:%f system:%f", data->minutes_alive, user, system);
    }
    wifi_util_info_print(WIFI_ANALYTICS, analytics_format_mgr_core, "keep-alive", temp_str);

    memcpy(&data->last_usage, &usage, sizeof(struct rusage));

    memset(client_mac, 0, sizeof(client_mac));
    memset(sta_stats_str, 0, sizeof(sta_stats_str));

    for (radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
        memset(&radio_stats, 0, sizeof(radio_stats));
        memset(temp_str, 0, sizeof(temp_str));
        if (get_dev_stats_for_radio(radio_index, (radio_data_t *)&radio_stats) == RETURN_OK) {
            snprintf(temp_str, sizeof(temp_str), "Radio%u_Stats channel:%d bw:%s noise_floor:%d channel_util:%d channel_interference:%d", radio_index,
                       radio_stats.primary_radio_channel, radio_stats.channel_bandwidth, radio_stats.NoiseFloor, radio_stats.channelUtil, radio_stats.channelInterference);
            wifi_util_info_print(WIFI_ANALYTICS, analytics_format_hal_core, "radio_stats", temp_str);
        }
    }

    sta_map = data->sta_map;
    sta_info = hash_map_get_first(sta_map);
    while (sta_info != NULL) {
        memset(temp_str, 0, sizeof(temp_str));
        memset(client_mac, 0, sizeof(client_mac));
        memset(sta_stats_str, 0, sizeof(sta_stats_str));
        sta_data = (sta_data_t *)get_stats_for_sta(sta_info->ap_index, sta_info->sta_mac);
        if (sta_data != NULL) {
            dev_stats = &sta_data->dev_stats;
            to_mac_str(sta_info->sta_mac, client_mac);
            snprintf(sta_stats_str, sizeof(sta_stats_str), "rssi:%ddbm good/bad rssi:%d/%d rapid reconnects:%d vap index:%u",
                               dev_stats->cli_RSSI, sta_data->good_rssi_time, sta_data->bad_rssi_time,
                               sta_data->rapid_reconnects, sta_info->ap_index);
            snprintf(temp_str, sizeof(temp_str), "\"%s\"", client_mac);
            wifi_util_info_print(WIFI_ANALYTICS, analytics_format_generic, temp_str, "CORE", "stats", sta_stats_str);
        }
        sta_info = hash_map_get_next(sta_map, sta_info);
    }
}
