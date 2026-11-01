/*
 * HANDLER: convert_channel_width_to_str
 *
 * Function copied VERBATIM from OneWifi source/apps/blaster/wifi_blaster.c
 * (only "static" dropped so the runner can call it). No fixes.
 * Local static arrays:
 *   - arr_str[][8]  : parallel string table ("20".."160")
 *   - arr_enum[]    : parallel enum table
 * The loop runs i < ARRAY_SIZE(arr_enum) and indexes arr_str[i] (same count),
 * then snprintf(str, len, "%s", arr_str[i]) into the caller's str (bounded
 * by len).
 *
 * The RUNNER poisons the caller's str past len. arr_str / arr_enum are
 * static const globals (auto-guarded by ASan).
 *
 * Scaffolding (NOT the function under test): ARRAY_SIZE from lib/const;
 * wifi_channelBandwidth_t values from the HAL; wifi_util_dbg_print formats.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "common.h"

/* --- scaffolding --- */
#define WIFI_BLASTER 0
#define ARRAY_SIZE(x)  ((unsigned int)(sizeof(x) / sizeof(x[0])))   /* lib/const/const.h */

static void ccw_print(int module, const char *fmt, ...)
{
    char scratch[512]; va_list ap; (void)module;
    va_start(ap, fmt); vsnprintf(scratch, sizeof(scratch), fmt, ap); va_end(ap);
}
#define wifi_util_dbg_print  ccw_print

/* --- copied verbatim from source/apps/blaster/wifi_blaster.c (only "static" dropped) --- */
void convert_channel_width_to_str(wifi_channelBandwidth_t cw, char *str, size_t len)
{
    static const char arr_str[][8] =
    {
        "20",
        "40",
        "80",
        "160",
#ifdef CONFIG_IEEE80211BE
        "320",
#endif /* CONFIG_IEEE80211BE */
    };
    static const wifi_channelBandwidth_t arr_enum[] =
    {
        WIFI_CHANNELBANDWIDTH_20MHZ,
        WIFI_CHANNELBANDWIDTH_40MHZ,
        WIFI_CHANNELBANDWIDTH_80MHZ,
        WIFI_CHANNELBANDWIDTH_160MHZ,
#ifdef CONFIG_IEEE80211BE
        WIFI_CHANNELBANDWIDTH_320MHZ,
#endif /* CONFIG_IEEE80211BE */
    };

    for (size_t i = 0; i < ARRAY_SIZE(arr_enum); i++) {
        if (arr_enum[i] == cw) {
            snprintf(str, len, "%s", arr_str[i]);
            break;
        }
    }

    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d %d converted to %s\n",__func__,__LINE__, cw, str);
}
