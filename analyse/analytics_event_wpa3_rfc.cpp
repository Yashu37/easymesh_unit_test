/*
 * HANDLER: analytics_event_wpa3_rfc
 *
 * Function copied VERBATIM from OneWifi source/apps/analytics/wifi_analytics.c.
 * No fixes. Local str[32] is filled by
 *   snprintf(str, sizeof(str), "%s", (*rfc == 1) ? "True" : "False")
 * (longest: "False" = 5 chars). arg is a single bool.
 *
 * Redirect: snprintf() -> awr_snprintf(): real vsnprintf on the runner slot
 * awr_slot with the SAME size (32), then copied into str. The RUNNER
 * poisons awr_slot past 32 and the caller's bool past sizeof(bool).
 * str is also guarded by ASan stack redzones.
 *
 * Scaffolding (NOT the function under test): wifi_util_info_print really
 * formats its arguments.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "common.h"

/* --- scaffolding --- */
#define RETURN_OK 0
#define WIFI_ANALYTICS 0
#define analytics_format_dml_core    "DML -> CORE : %s : %s\r\n"     /* wifi_analytics.h */

static void wifi_util_info_print(int module, const char *fmt, ...)
{
    char scratch[4096];
    va_list ap; (void)module;
    va_start(ap, fmt);
    vsnprintf(scratch, sizeof(scratch), fmt, ap);
    va_end(ap);
}

static int awr_snprintf(char *out, size_t sz, const char *fmt, ...)
{
    int r;
    va_list ap;
    if (sz > AWR_SLOT_SZ) sz = AWR_SLOT_SZ;
    memset(awr_slot, 0, sz);
    va_start(ap, fmt);
    r = vsnprintf(awr_slot, sz, fmt, ap);
    va_end(ap);
    memcpy(out, awr_slot, sz);
    awr_len = strnlen(awr_slot, sz);
    return r;
}
#define snprintf(o, n, ...)  awr_snprintf((o), (n), __VA_ARGS__)

/* --- copied verbatim from source/apps/analytics/wifi_analytics.c --- */
int analytics_event_wpa3_rfc(wifi_app_t *apps, void *arg)
{
    bool *rfc = (bool *)arg;
    char str[32];
    memset(&str, 0, sizeof(str));

    snprintf(str, sizeof(str), "%s", (*rfc == 1)?"True":"False");
    wifi_util_info_print(WIFI_ANALYTICS, analytics_format_dml_core, "wpa3_rfc", str);
    return RETURN_OK;
}
