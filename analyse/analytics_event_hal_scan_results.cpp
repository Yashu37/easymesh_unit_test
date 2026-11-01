/*
 * HANDLER: analytics_event_hal_scan_results
 *
 * Function copied VERBATIM from OneWifi source/apps/analytics/wifi_analytics.c.
 * No fixes. Local str[128] is filled by
 *   snprintf(str, sizeof(str), "radio:%u scancount:%d", radio_index, num)
 * (longest: "radio:4294967295 scancount:-2147483648" = 38 chars).
 *
 * Redirect: snprintf() -> asr_snprintf(): real vsnprintf on the runner slot
 * asr_slot with the SAME size (128), then copied into str. The RUNNER
 * poisons asr_slot past 128 and the caller's arg past its size. str is also
 * guarded by ASan stack redzones.
 *
 * Scaffolding (NOT the function under test): wifi_util_info_print /
 * wifi_util_error_print really format their arguments; scan_results_t is a
 * subset in common.h (radio_index, bss[] placeholder, num).
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

static void asr_print(int module, const char *fmt, ...)
{
    char scratch[4096];
    va_list ap; (void)module;
    va_start(ap, fmt);
    vsnprintf(scratch, sizeof(scratch), fmt, ap);
    va_end(ap);
}
#define wifi_util_info_print   asr_print
#define wifi_util_error_print  asr_print

static int asr_snprintf(char *out, size_t sz, const char *fmt, ...)
{
    int r;
    va_list ap;
    if (sz > ASR_SLOT_SZ) sz = ASR_SLOT_SZ;
    memset(asr_slot, 0, sz);
    va_start(ap, fmt);
    r = vsnprintf(asr_slot, sz, fmt, ap);
    va_end(ap);
    memcpy(out, asr_slot, sz);
    asr_len = strnlen(asr_slot, sz);
    asr_calls++;
    return r;
}
#define snprintf(o, n, ...)  asr_snprintf((o), (n), __VA_ARGS__)

/* --- copied verbatim from source/apps/analytics/wifi_analytics.c --- */
int analytics_event_hal_scan_results(wifi_app_t *apps, void *arg)
{
    scan_results_t *results = (scan_results_t *)arg;
    char    str[128] = { 0 };

    if (results == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d: input arg is NULL\n",__func__, __LINE__);
        return RETURN_ERR;
    }

    snprintf(str, sizeof(str), "radio:%u scancount:%d", results->radio_index, results->num);

    wifi_util_info_print(WIFI_ANALYTICS, analytics_format_hal_core, "scan results", str);

    return RETURN_OK;
}
