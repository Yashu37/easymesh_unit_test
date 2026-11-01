/*
 * HANDLER: analytics_event_sta_connect_in_progress
 *
 * Function copied VERBATIM from OneWifi source/apps/analytics/wifi_analytics.c.
 * No fixes. Local arrays and their writers:
 *   - bssid_str (mac_addr_str_t, char[18]) <- to_mac_str(bssid, bssid_str)
 *                                              (snprintf(key, 18): 17 chars + NUL)
 *   - temp_str[512] <- snprintf(temp_str, sizeof(temp_str),
 *                               "start connection : bssid:%s", bssid_str)  (42 chars)
 *
 * Redirects (write into runner slots of the SAME size, then copy back):
 *   - to_mac_str() -> scp_to_mac_str(): verbatim to_mac_str on scp_slot_mac (18).
 *   - snprintf()   -> scp_snprintf(): real vsnprintf on scp_slot_tmp (512).
 * The RUNNER poisons scp_slot_mac past 18, scp_slot_tmp past 512, and the
 * caller's arg (bss_candidate_t) past its size. The arrays are also guarded
 * by ASan stack redzones.
 *
 * Scaffolding (NOT the function under test): wifi_util_info_print /
 * wifi_util_error_print really format their arguments; bss_candidate_t is
 * a packed subset in common.h (external_ap.bssid first, as in the HAL).
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

static void scp_print(int module, const char *fmt, ...)
{
    char scratch[4096];
    va_list ap; (void)module;
    va_start(ap, fmt);
    vsnprintf(scratch, sizeof(scratch), fmt, ap);
    va_end(ap);
}
#define wifi_util_info_print   scp_print
#define wifi_util_error_print  scp_print

/* verbatim from source/utils/wifi_util.c */
static char *to_mac_str(mac_address_t mac, mac_addr_str_t key)
{
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return (char *)key;
}

/* redirects: write into runner slots of the same size as the real array */
static char *scp_to_mac_str(unsigned char *mac, char *key)
{
    memset(scp_slot_mac, 0, SCP_MAC_SZ);
    to_mac_str(mac, scp_slot_mac);
    memcpy(key, scp_slot_mac, SCP_MAC_SZ);
    scp_mac_calls++;
    return key;
}
static int scp_snprintf(char *out, size_t sz, const char *fmt, ...)
{
    int r;
    va_list ap;
    if (sz > SCP_TMP_SZ) sz = SCP_TMP_SZ;
    memset(scp_slot_tmp, 0, sz);
    va_start(ap, fmt);
    r = vsnprintf(scp_slot_tmp, sz, fmt, ap);
    va_end(ap);
    memcpy(out, scp_slot_tmp, sz);
    scp_tmp_len = strnlen(scp_slot_tmp, sz);
    return r;
}
#define to_mac_str(m, k)     scp_to_mac_str((m), (k))
#define snprintf(o, n, ...)  scp_snprintf((o), (n), __VA_ARGS__)

/* --- copied verbatim from source/apps/analytics/wifi_analytics.c --- */
int analytics_event_sta_connect_in_progress(wifi_app_t *apps, void *arg)
{
    bss_candidate_t  *candidate = (bss_candidate_t *)arg;
    char temp_str[512];
    mac_addr_str_t bssid_str;
    if (candidate == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d: input arg is NULL\n",__func__, __LINE__);
        return RETURN_ERR;
    }

    to_mac_str(candidate->external_ap.bssid, bssid_str);
    snprintf(temp_str, sizeof(temp_str), "start connection : bssid:%s", bssid_str);
    wifi_util_info_print(WIFI_ANALYTICS, analytics_format_core_hal, "sta status", temp_str);
    return RETURN_OK;
}
