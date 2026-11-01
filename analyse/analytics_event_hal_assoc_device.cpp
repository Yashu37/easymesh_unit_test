/*
 * HANDLER: analytics_event_hal_assoc_device
 *
 * Function copied VERBATIM from OneWifi source/apps/analytics/wifi_analytics.c.
 * No fixes. Local arrays and their writers:
 *   - client_mac[32] <- to_mac_str(mac, client_mac)  (snprintf(key, 18)),
 *                       then str_tolower(client_mac) in place
 *   - temp_str[64]   <- sprintf(temp_str, "\"%s\" vap index:%d", ...)
 *                       (NO size: longest is 2+17+11+11 = 41 chars)
 * Note: malloc(sizeof(analytics_sta_info_t)) is used without a NULL check
 * (checked by the last case).
 *
 * Redirects (write into runner slots of the SAME size, then copy back):
 *   - to_mac_str() -> aad_to_mac_str(): verbatim to_mac_str on aad_slot_mac (32).
 *   - sprintf()    -> aad_sprintf(): real vsprintf on aad_slot_tmp (64).
 *   - malloc()     -> aad_malloc(): runner pool slot (tail past
 *     sizeof(analytics_sta_info_t)).
 * The RUNNER poisons aad_slot_mac past 32, aad_slot_tmp past 64, each pool
 * slot past sizeof(analytics_sta_info_t), and the caller's arg / apps
 * buffers past their sizes. The arrays are also guarded by ASan redzones.
 *
 * Scaffolding (NOT the function under test):
 *   - str_tolower: verbatim from lib/common/util.c.
 *   - hash_map_get / hash_map_put: stubs over a tiny runner table
 *     (put frees the strdup'd key).
 *   - wifi_util_info_print: really formats its arguments.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include "common.h"

/* --- scaffolding --- */
#define RETURN_OK 0
#define WIFI_ANALYTICS 0
#define analytics_format_hal_core    "HAL -> CORE : %s : %s\r\n"     /* wifi_analytics.h */

static void wifi_util_info_print(int module, const char *fmt, ...)
{
    char scratch[4096];
    va_list ap; (void)module;
    va_start(ap, fmt);
    vsnprintf(scratch, sizeof(scratch), fmt, ap);
    va_end(ap);
}

/* verbatim from source/utils/wifi_util.c */
static char *to_mac_str(mac_address_t mac, mac_addr_str_t key)
{
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return (char *)key;
}

/* verbatim from lib/common/util.c */
static char *str_tolower(char *str)
{
    unsigned char *s = (unsigned char*)str;
    while (s && *s) { *s =(unsigned char) tolower(*s); s++; }
    return str;
}

static void *aad_hash_map_get(void *map, const char *key)
{
    (void)map;
    aad_get_calls++;
    return (aad_existing && !strcmp(key, aad_existing_key)) ? aad_existing : NULL;
}
static int8_t aad_hash_map_put(void *map, char *key, void *data)
{
    (void)map;
    snprintf(aad_put_key, sizeof(aad_put_key), "%s", key);
    aad_put_data = data;
    free(key);
    return 0;
}
static void *aad_malloc(size_t sz)
{
    if (aad_malloc_fail || sz != sizeof(analytics_sta_info_t) || aad_pool_used >= AAD_POOL_SLOTS) return NULL;
    return aad_pool[aad_pool_used++];
}

/* redirects: write into runner slots of the same size as the real array */
static char *aad_to_mac_str(mac_address_t mac, char *key)
{
    memset(aad_slot_mac, 0, AAD_MAC_SZ);
    to_mac_str(mac, aad_slot_mac);
    memcpy(key, aad_slot_mac, AAD_MAC_SZ);
    return key;
}
static int aad_sprintf(char *out, const char *fmt, ...)
{
    int r;
    va_list ap;
    memset(aad_slot_tmp, 0, AAD_TMP_SZ);
    va_start(ap, fmt);
    r = vsprintf(aad_slot_tmp, fmt, ap);     /* unbounded, like the real sprintf */
    va_end(ap);
    memcpy(out, aad_slot_tmp, AAD_TMP_SZ);
    aad_tmp_len = strnlen(aad_slot_tmp, AAD_TMP_SZ);
    return r;
}
#define to_mac_str(m, k)        aad_to_mac_str((m), (k))
#define sprintf(o, ...)         aad_sprintf((o), __VA_ARGS__)
#define hash_map_get(m, k)      aad_hash_map_get((m), (k))
#define hash_map_put(m, k, d)   aad_hash_map_put((m), (k), (d))
#define malloc(s)               aad_malloc(s)

/* --- copied verbatim from source/apps/analytics/wifi_analytics.c --- */
int analytics_event_hal_assoc_device(wifi_app_t *apps, void *arg)
{
    char client_mac[32];
    char temp_str[64];
    hash_map_t           *sta_map;
    analytics_sta_info_t *sta_info;

    memset(client_mac, 0, sizeof(client_mac));
    memset(temp_str, 0, sizeof(temp_str));

    assoc_dev_data_t *assoc_data = (assoc_dev_data_t *)arg;

    (char *)to_mac_str(assoc_data->dev_stats.cli_MACAddress, client_mac);

    str_tolower(client_mac);

    sprintf(temp_str, "\"%s\" vap index:%d", client_mac, assoc_data->ap_index);

    wifi_util_info_print(WIFI_ANALYTICS, analytics_format_hal_core, "connect", temp_str);

    sta_map = apps->data.u.analytics.sta_map;

    if ((sta_info = (analytics_sta_info_t *)hash_map_get(sta_map, client_mac)) == NULL) {
        sta_info = malloc(sizeof(analytics_sta_info_t));
        sta_info->ap_index = assoc_data->ap_index;
        memcpy(sta_info->sta_mac, assoc_data->dev_stats.cli_MACAddress, sizeof(mac_address_t));
        hash_map_put(sta_map, strdup(client_mac), sta_info);
    } else {
        sta_info->ap_index = assoc_data->ap_index;
        memcpy(sta_info->sta_mac, assoc_data->dev_stats.cli_MACAddress, sizeof(mac_address_t));
    }

    return RETURN_OK;
}
