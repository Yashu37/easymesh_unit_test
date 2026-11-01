/*
 * HANDLER: analytics_event_hal_potential_misconfiguration
 *
 * Function copied VERBATIM from OneWifi source/apps/analytics/wifi_analytics.c.
 * No fixes. Local temp_str[128] is filled by an UNBOUNDED
 *   sprintf(temp_str, "authentication frame not received from mac:\"%s\" after %d frame",
 *           ttl_data->mac_str, ttl_data->max_probe_ttl_cnt)
 * mac_str is mac_addr_str_t (char[18]) and the LAST field of the packed
 * probe_ttl_data_t; the only producer (levl update_probe_map) fills it with
 * snprintf(.., sizeof(mac_str), ..) so it is always NUL-terminated.
 * Longest: 44 + 17 + 8 + 11 ("-2147483648") + 6 = 86 chars.
 *
 * Redirect: sprintf() -> apm_sprintf(): real (unbounded) vsprintf on the
 * runner slot apm_slot with the SAME size (128), then copied into temp_str.
 * The RUNNER poisons apm_slot past 128 and the caller's arg past its size
 * (so reading past mac_str is caught). temp_str is also guarded by ASan
 * stack redzones.
 *
 * Scaffolding (NOT the function under test): wifi_util_info_print really
 * formats its arguments; probe_ttl_data_t copied from levl/wifi_levl.h.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
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

static int apm_sprintf(char *out, const char *fmt, ...)
{
    int r;
    va_list ap;
    memset(apm_slot, 0, APM_SLOT_SZ);
    va_start(ap, fmt);
    r = vsprintf(apm_slot, fmt, ap);     /* unbounded, like the real sprintf */
    va_end(ap);
    memcpy(out, apm_slot, APM_SLOT_SZ);
    apm_len = strnlen(apm_slot, APM_SLOT_SZ);
    return r;
}
#define sprintf(o, ...)  apm_sprintf((o), __VA_ARGS__)

/* --- copied verbatim from source/apps/analytics/wifi_analytics.c --- */
int analytics_event_hal_potential_misconfiguration(wifi_app_t *apps, void *arg)
{
    probe_ttl_data_t *ttl_data = (probe_ttl_data_t *)arg;
    char temp_str[128];
    memset(temp_str, 0, sizeof(temp_str));

    sprintf(temp_str, "authentication frame not received from mac:\"%s\" after %d frame", ttl_data->mac_str, ttl_data->max_probe_ttl_cnt);
    wifi_util_info_print(WIFI_ANALYTICS, analytics_format_hal_core, "no_auth", temp_str);
    return RETURN_OK;
}
