/*
 * HANDLER: analytics_event_hal_sta_conn_status
 *
 * Function copied VERBATIM from OneWifi source/apps/analytics/wifi_analytics.c.
 * No fixes. Local temp_str[128] is filled by
 *   snprintf(temp_str, sizeof(temp_str), ...)   (one per connect_status case)
 * and then printed by wifi_util_info_print.
 *
 * Redirect: snprintf() -> scs_snprintf(): real vsnprintf on the runner slot
 * scs_slot with the SAME size (128), then copied into temp_str. The RUNNER
 * poisons scs_slot past 128 (and the caller's arg struct past its size), so
 * a write past 128 aborts. temp_str is also guarded by ASan stack redzones.
 *
 * Scaffolding (NOT the function under test): wifi_util_info_print /
 * wifi_util_error_print really format their arguments; rdk_sta_data_t is a
 * subset (stats.connect_status, stats.vap_index, bss_info.bssid) in common.h.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "common.h"

/* --- scaffolding --- */
#define RETURN_OK   0
#define RETURN_ERR -1
#define WIFI_ANALYTICS 0
#define WIFI_APPS      0
#define analytics_format_hal_core    "HAL -> CORE : %s : %s\r\n"     /* wifi_analytics.h */

static void scs_print(int module, const char *fmt, ...)
{
    char scratch[4096];
    va_list ap; (void)module;
    va_start(ap, fmt);
    vsnprintf(scratch, sizeof(scratch), fmt, ap);
    va_end(ap);
}
#define wifi_util_info_print   scs_print
#define wifi_util_error_print  scs_print

static int scs_snprintf(char *out, size_t sz, const char *fmt, ...)
{
    int r;
    va_list ap;
    if (sz > SCS_SLOT_SZ) sz = SCS_SLOT_SZ;
    memset(scs_slot, 0, sz);
    va_start(ap, fmt);
    r = vsnprintf(scs_slot, sz, fmt, ap);
    va_end(ap);
    memcpy(out, scs_slot, sz);
    scs_len = strnlen(scs_slot, sz);
    scs_calls++;
    return r;
}
#define snprintf(o, n, ...)  scs_snprintf((o), (n), __VA_ARGS__)

/* --- copied verbatim from source/apps/analytics/wifi_analytics.c --- */
int analytics_event_hal_sta_conn_status(wifi_app_t *apps, void *arg)
{
    rdk_sta_data_t *sta_data = (rdk_sta_data_t *)arg;
    char temp_str[128];

    if (sta_data == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d: input arg is NULL\n",__func__, __LINE__);
        return RETURN_ERR;
    }

    memset(temp_str, 0, sizeof(temp_str));
    switch(sta_data->stats.connect_status) {
        case wifi_connection_status_connected:
            snprintf(temp_str, sizeof(temp_str), "connected : vap_index %d bssid %02x:%02x:%02x:%02x:%02x:%02x",
                    sta_data->stats.vap_index, sta_data->bss_info.bssid[0], sta_data->bss_info.bssid[1],
        sta_data->bss_info.bssid[2], sta_data->bss_info.bssid[3],
        sta_data->bss_info.bssid[4], sta_data->bss_info.bssid[5]);
            wifi_util_info_print(WIFI_ANALYTICS, analytics_format_hal_core, "sta status", temp_str);
        break;
        case wifi_connection_status_disconnected:
            snprintf(temp_str, sizeof(temp_str), "disconnected : vap_index %d bssid %02x:%02x:%02x:%02x:%02x:%02x",
                    sta_data->stats.vap_index, sta_data->bss_info.bssid[0], sta_data->bss_info.bssid[1],
                    sta_data->bss_info.bssid[2], sta_data->bss_info.bssid[3],
                    sta_data->bss_info.bssid[4], sta_data->bss_info.bssid[5]);
            wifi_util_info_print(WIFI_ANALYTICS, analytics_format_hal_core, "sta status", temp_str);
        break;
        case wifi_connection_status_ap_not_found:
            snprintf(temp_str, sizeof(temp_str), "disconnected AP not found : vap_index %d",
                    sta_data->stats.vap_index);
            wifi_util_info_print(WIFI_ANALYTICS, analytics_format_hal_core, "sta status", temp_str);
        break;
        default:
        break;
    }

    return RETURN_OK;
}
