/*
 * HANDLER: analytics_event_hal_channel_change
 *
 * Function copied VERBATIM from OneWifi source/apps/analytics/wifi_analytics.c.
 * No fixes. Local arrays:
 *   - desc[128]       <- snprintf(desc, sizeof(desc), ...)  (3 formats)
 *   - static dfs_states[6] (const char *) indexed by ch->sub_event, guarded
 *     by sub_event < WIFI_EVENT_RADAR_DETECTED (0) || > WIFI_EVENT_RADAR_CAC_STARTED (5).
 *     The enum has only non-negative values, so sub_event compares as
 *     unsigned: a "negative" value wraps high and is rejected.
 *
 * Redirect: snprintf() -> acc_snprintf(): real vsnprintf on the runner slot
 * acc_slot with the SAME size (128), then copied into desc. The RUNNER
 * poisons acc_slot past 128 and the caller's arg past its size. desc and
 * dfs_states are also guarded by ASan (stack / global redzones).
 *
 * Scaffolding (NOT the function under test): wifi_util_info_print really
 * formats its arguments; the enums and the packed
 * wifi_channel_change_event_t are copied from the HAL headers into common.h.
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

static int acc_snprintf(char *out, size_t sz, const char *fmt, ...)
{
    int r;
    va_list ap;
    if (sz > ACC_SLOT_SZ) sz = ACC_SLOT_SZ;
    memset(acc_slot, 0, sz);
    va_start(ap, fmt);
    r = vsnprintf(acc_slot, sz, fmt, ap);
    va_end(ap);
    memcpy(out, acc_slot, sz);
    acc_len = strnlen(acc_slot, sz);
    acc_calls++;
    return r;
}
#define snprintf(o, n, ...)  acc_snprintf((o), (n), __VA_ARGS__)

/* --- copied verbatim from source/apps/analytics/wifi_analytics.c --- */
int analytics_event_hal_channel_change(wifi_app_t *apps, void *arg)
{
    char    desc[128] = { 0 };
    wifi_channel_change_event_t *ch = (wifi_channel_change_event_t *)arg;
    static const char *dfs_states[] = { "Radar detected",
                                        "CAC finished",
                                        "CAC aborted",
                                        "NOP finished",
                                        "PRE-CAC expired",
                                        "CAC started"};

    if(ch->event == WIFI_EVENT_DFS_RADAR_DETECTED) {
        if(ch->sub_event < WIFI_EVENT_RADAR_DETECTED || ch->sub_event > WIFI_EVENT_RADAR_CAC_STARTED) {
            snprintf(desc, sizeof(desc), "Unknown ch:%d bw:%d radio:%d", ch->channel, ch->channelWidth, ch->radioIndex);
        } else {
            snprintf(desc, sizeof(desc), "%s ch:%d bw:%d radio:%d", dfs_states[ch->sub_event], ch->channel, ch->channelWidth, ch->radioIndex);
        }
        wifi_util_info_print(WIFI_ANALYTICS, analytics_format_hal_core, "DFS event", desc);
    } else {
        snprintf(desc, sizeof(desc), "ch:%d bw:%d radio:%d", ch->channel, ch->channelWidth, ch->radioIndex);
        wifi_util_info_print(WIFI_ANALYTICS, analytics_format_hal_core, "channel change", desc);
    }

    return RETURN_OK;
}
