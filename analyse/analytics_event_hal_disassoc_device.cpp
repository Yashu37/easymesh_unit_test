/*
 * HANDLER: analytics_event_hal_disassoc_device
 *
 * Function copied VERBATIM from OneWifi source/apps/analytics/wifi_analytics.c.
 * No fixes. Local arrays and their writers:
 *   - client_mac[32] <- to_mac_str(mac, client_mac)  (snprintf(key, 18)),
 *                       then str_tolower(client_mac) in place
 *   - temp_str[64]   <- sprintf(temp_str, "\"%s\" vap index:%d reason:%d", ...)
 *                       (NO size: longest is 2+17+11+11+8+11 = 60 chars + NUL)
 *
 * Redirects (write into runner slots of the SAME size, then copy back):
 *   - to_mac_str() -> add_to_mac_str(): verbatim to_mac_str on add_slot_mac (32).
 *   - sprintf()    -> add_sprintf(): real vsprintf on add_slot_tmp (64).
 * The RUNNER poisons add_slot_mac past 32, add_slot_tmp past 64, and the
 * caller's arg / apps buffers past their sizes. The arrays are also guarded
 * by ASan stack redzones.
 *
 * Scaffolding (NOT the function under test):
 *   - str_tolower: verbatim from lib/common/util.c.
 *   - hash_map_get / hash_map_remove: stubs over one runner entry.
 *   - free(): records the pointer (the entry is runner memory).
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

static void *add_hash_map_get(void *map, const char *key)
{
    (void)map;
    snprintf(add_key_seen, sizeof(add_key_seen), "%s", key);
    return (add_entry && !strcmp(key, add_entry_key)) ? add_entry : NULL;
}
static void *add_hash_map_remove(void *map, const char *key)
{
    (void)map;
    add_remove_calls++;
    if (add_remove_null) return NULL;
    return (add_entry && !strcmp(key, add_entry_key)) ? add_entry : NULL;
}
static void add_free(void *p) { add_freed = p; }

/* redirects: write into runner slots of the same size as the real array */
static char *add_to_mac_str(mac_address_t mac, char *key)
{
    memset(add_slot_mac, 0, ADD_MAC_SZ);
    to_mac_str(mac, add_slot_mac);
    memcpy(key, add_slot_mac, ADD_MAC_SZ);
    return key;
}
static int add_sprintf(char *out, const char *fmt, ...)
{
    int r;
    va_list ap;
    memset(add_slot_tmp, 0, ADD_TMP_SZ);
    va_start(ap, fmt);
    r = vsprintf(add_slot_tmp, fmt, ap);     /* unbounded, like the real sprintf */
    va_end(ap);
    memcpy(out, add_slot_tmp, ADD_TMP_SZ);
    add_tmp_len = strnlen(add_slot_tmp, ADD_TMP_SZ);
    return r;
}
#define to_mac_str(m, k)        add_to_mac_str((m), (k))
#define sprintf(o, ...)         add_sprintf((o), __VA_ARGS__)
#define hash_map_get(m, k)      add_hash_map_get((m), (k))
#define hash_map_remove(m, k)   add_hash_map_remove((m), (k))
#define free(p)                 add_free(p)

/* --- copied verbatim from source/apps/analytics/wifi_analytics.c --- */
int analytics_event_hal_disassoc_device(wifi_app_t *apps, void *arg)
{
    char client_mac[32];
    char temp_str[64];
    hash_map_t            *sta_map;
    analytics_sta_info_t  *sta_info;
    memset(client_mac, 0, sizeof(client_mac));
    memset(temp_str, 0, sizeof(temp_str));

    assoc_dev_data_t *assoc_data = (assoc_dev_data_t *)arg;

    sta_map = apps->data.u.analytics.sta_map;

    (char *)to_mac_str(assoc_data->dev_stats.cli_MACAddress, client_mac);
    str_tolower(client_mac);
    sprintf(temp_str, "\"%s\" vap index:%d reason:%d", client_mac, assoc_data->ap_index, assoc_data->reason);
    wifi_util_info_print(WIFI_ANALYTICS, analytics_format_hal_core, "disconnect", temp_str);

    sta_info = (analytics_sta_info_t *)hash_map_get(sta_map, client_mac);
    if (sta_info != NULL) {
        sta_info = hash_map_remove(sta_map, client_mac);
        if (sta_info != NULL) {
            free(sta_info);
        }
    }

    return RETURN_OK;
}
