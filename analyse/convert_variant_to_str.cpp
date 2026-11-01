/*
 * HANDLER: convert_variant_to_str
 *
 * Function copied VERBATIM from OneWifi source/apps/blaster/wifi_blaster.c
 * ("static" dropped so the runner can call it) plus one FIX.
 * Local static arrays arr_str[][8] / arr_enum[] (parallel). For each set
 * bit it does snprintf(str, len, "%s,", arr_str[i]); afterwards it trims the
 * trailing comma with:  str[strlen(str) - 1] = '\0';
 *
 * BUG (FIXED here): if NO arr_enum bit is set in `variant` (e.g. variant with
 * only WIFI_80211_VARIANT_H 0x10 / _AD 0x40, or 0), nothing is written, so
 * when `str` is empty strlen(str) == 0 and str[strlen(str) - 1] writes to
 * str[-1] -- an out-of-bounds write BEFORE the caller's buffer.
 *
 * The RUNNER places str after a poisoned guard region and poisons past len,
 * so the str[-1] write lands in poison. arr_str/arr_enum are static const
 * globals (auto-guarded by ASan).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "common.h"

/* --- scaffolding --- */
#define WIFI_BLASTER 0
#define ARRAY_SIZE(x)  ((unsigned int)(sizeof(x) / sizeof(x[0])))   /* lib/const/const.h */

static void cvs_print(int module, const char *fmt, ...)
{
    char scratch[512]; va_list ap; (void)module;
    va_start(ap, fmt); vsnprintf(scratch, sizeof(scratch), fmt, ap); va_end(ap);
}
#define wifi_util_dbg_print  cvs_print

/* --- copied verbatim from source/apps/blaster/wifi_blaster.c (only "static" dropped) --- */
void convert_variant_to_str(wifi_ieee80211Variant_t variant, char *str, size_t len)
{
    static const char arr_str[][8] =
    {
        "a",
        "b",
        "g",
        "n",
        "ac",
        "ax",
#ifdef CONFIG_IEEE80211BE
        "be",
#endif /* CONFIG_IEEE80211BE */
    };
    static const wifi_ieee80211Variant_t arr_enum[] =
    {
        WIFI_80211_VARIANT_A,
        WIFI_80211_VARIANT_B,
        WIFI_80211_VARIANT_G,
        WIFI_80211_VARIANT_N,
        WIFI_80211_VARIANT_AC,
        WIFI_80211_VARIANT_AX,
#ifdef CONFIG_IEEE80211BE
        WIFI_80211_VARIANT_BE,
#endif /* CONFIG_IEEE80211BE */
    };

    for (size_t i = 0; i < ARRAY_SIZE(arr_enum); i++) {
        if ((arr_enum[i] & variant) == arr_enum[i]) {
            snprintf(str, len, "%s,", arr_str[i]);
        }
    }

    size_t _l = strlen(str);
    if (_l > 0) str[_l - 1] = '\0';   /* FIX: guard the trailing-comma trim (was str[strlen(str)-1], str[-1] when empty) */
    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d 0x%X converted to %s\n",__func__,__LINE__, variant, str);
}
