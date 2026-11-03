/*
 * HANDLER: em_handle_failed_connection
 *
 * Copied VERBATIM from OneWifi source/apps/em/wifi_em.c (only "static"
 * dropped). Local arrays:
 *   - mac_addr_str_t sta_str, bss_str (char[18]) : bounded to_mac_str.
 *   - sta_fail_data_t sd / wifi_em_failed_conn_t fc : fixed structs, filled by
 *     memcpy of their own sizeof (bssid/sta_mac are 6-byte copies).
 * NULL arg and a missing vap are rejected. No array can be overrun -> SAFE.
 *
 * Scaffolding (NOT under test): getVapInfo / to_mac_str are stubbed;
 * em_publish_failed_connection is #define-redirected to a local stub so the
 * real symbol (its own TU) is not redefined. Driven by the hfc_* globals.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

#ifndef RETURN_OK
#define RETURN_OK  0
#endif
#ifndef RETURN_ERR
#define RETURN_ERR (-1)
#endif
#define WIFI_EM 0
#ifndef wifi_util_dbg_print
#define wifi_util_dbg_print(m, ...)   do {} while (0)
#define wifi_util_error_print(m, ...) do {} while (0)
#endif

typedef struct { union { struct { unsigned char bssid[6]; } bss_info; } u; } wifi_vap_info_t;

/* --- scaffolding stubs driven by hfc_* globals --- */
static wifi_vap_info_t hfc_vap;
static wifi_vap_info_t *getVapInfo(int ap_index)
{
    (void)ap_index;
    if (hfc_vap_null) return NULL;
    unsigned char b[6] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15};
    memcpy(hfc_vap.u.bss_info.bssid, b, 6);
    return &hfc_vap;
}
static char *to_mac_str(mac_address_t mac, mac_addr_str_t key)
{
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}
static int hfc_pub(const wifi_em_failed_conn_t *fc) { (void)fc; hfc_publish_calls++; return hfc_publish_fail ? RETURN_ERR : RETURN_OK; }
#define em_publish_failed_connection(fc)  hfc_pub((fc))

/* ================= VERBATIM from wifi_em.c (static dropped) ================= */
int em_handle_failed_connection(wifi_app_t *app, void *arg)
{
    sta_fail_data_t sd;
    wifi_vap_info_t *vap_info;
    wifi_em_failed_conn_t fc;
    mac_addr_str_t sta_str, bss_str;

    (void)app;

    if (arg == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d: NULL arg\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    /* Copy from the event-queue buffer into an aligned local before field access. */
    memcpy(&sd, arg, sizeof(sd));

    vap_info = getVapInfo(sd.ap_index);
    if (vap_info == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d: getVapInfo failed for ap_index=%d\n",
            __func__, __LINE__, sd.ap_index);
        return RETURN_ERR;
    }

    memset(&fc, 0, sizeof(fc));
    memcpy(fc.bssid,   vap_info->u.bss_info.bssid, sizeof(fc.bssid));
    memcpy(fc.sta_mac, sd.sta_mac,                 sizeof(fc.sta_mac));
    fc.status = sd.status;
    fc.reason = sd.reason;

    to_mac_str(fc.bssid,   bss_str);
    to_mac_str(fc.sta_mac, sta_str);
    wifi_util_dbg_print(WIFI_EM,
        "%s:%d: failed_connection bssid=%s sta=%s status=%u reason=%u\n",
        __func__, __LINE__, bss_str, sta_str,
        (unsigned int)fc.status, (unsigned int)fc.reason);

    return em_publish_failed_connection(&fc);
}
