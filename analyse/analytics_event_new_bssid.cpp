/*
 * HANDLER: analytics_event_new_bssid
 *
 * Function copied VERBATIM from OneWifi source/apps/analytics/wifi_analytics.c.
 * No fixes ("static" dropped so the runner can call it). Local arrays and their writers:
 *   - bssid_str (mac_addr_str_t, char[18]) <- to_mac_str(new_bss.external_ap.bssid, bssid_str)
 *                                              (snprintf(key, 18): 17 chars + NUL)
 *   - temp_str[512] <- snprintf(temp_str, sizeof(temp_str),
 *       "new bssid : vap_index:%d bssid:%s freq:%d", new_bss.vap_index, bssid_str, new_bss.external_ap.freq)
 *       (longest: 22 + 11 + 7 + 17 + 6 + 11 = 74 chars)
 *
 * Redirects (write into runner slots of the SAME size, then copy back):
 *   - to_mac_str() -> anb_to_mac_str(): verbatim to_mac_str on anb_slot_mac (18).
 *   - snprintf()   -> anb_snprintf(): real vsnprintf on anb_slot_tmp (512).
 * The RUNNER poisons anb_slot_mac past 18, anb_slot_tmp past 512, and the
 * caller's arg (vap_svc_ext_t) past its size. The arrays are also guarded
 * by ASan stack redzones.
 *
 * Scaffolding (NOT the function under test): wifi_util_info_print /
 * wifi_util_error_print really format their arguments; vap_svc_ext_t is a
 * packed subset in common.h (bss_candidate_t.vap_index and
 * wifi_bss_info_t.freq at their real offsets).
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
#define analytics_format_core_hal    "CORE -> HAL : %s : %s\r\n"     /* wifi_analytics.h */

static void anb_print(int module, const char *fmt, ...)
{
    char scratch[4096];
    va_list ap; (void)module;
    va_start(ap, fmt);
    vsnprintf(scratch, sizeof(scratch), fmt, ap);
    va_end(ap);
}
#define wifi_util_info_print   anb_print
#define wifi_util_error_print  anb_print

/* verbatim from source/utils/wifi_util.c */
static char *to_mac_str(mac_address_t mac, mac_addr_str_t key)
{
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return (char *)key;
}

/* redirects: write into runner slots of the same size as the real array */
static char *anb_to_mac_str(unsigned char *mac, char *key)
{
    memset(anb_slot_mac, 0, ANB_MAC_SZ);
    to_mac_str(mac, anb_slot_mac);
    memcpy(key, anb_slot_mac, ANB_MAC_SZ);
    anb_mac_calls++;
    return key;
}
static int anb_snprintf(char *out, size_t sz, const char *fmt, ...)
{
    int r;
    va_list ap;
    if (sz > ANB_TMP_SZ) sz = ANB_TMP_SZ;
    memset(anb_slot_tmp, 0, sz);
    va_start(ap, fmt);
    r = vsnprintf(anb_slot_tmp, sz, fmt, ap);
    va_end(ap);
    memcpy(out, anb_slot_tmp, sz);
    anb_tmp_len = strnlen(anb_slot_tmp, sz);
    return r;
}
#define to_mac_str(m, k)     anb_to_mac_str((m), (k))
#define snprintf(o, n, ...)  anb_snprintf((o), (n), __VA_ARGS__)

/* --- copied verbatim from source/apps/analytics/wifi_analytics.c (only "static" dropped) --- */
int analytics_event_new_bssid(wifi_app_t *apps, void *arg)
{
    char temp_str[512];
    mac_addr_str_t bssid_str;
    vap_svc_ext_t *ext = (vap_svc_ext_t *)arg;

    if (ext == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: input arg is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    to_mac_str(ext->new_bss.external_ap.bssid, bssid_str);
    snprintf(temp_str, sizeof(temp_str), "new bssid : vap_index:%d bssid:%s freq:%d",
        ext->new_bss.vap_index, bssid_str, ext->new_bss.external_ap.freq);
    wifi_util_info_print(WIFI_ANALYTICS, analytics_format_core_hal, "sta status", temp_str);
    return RETURN_OK;
}
