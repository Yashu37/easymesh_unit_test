/*
 * HANDLER: em_process_beacon_rep
 *
 * Copied VERBATIM from OneWifi source/apps/em/wifi_em.c (only "static"
 * dropped). Local arrays:
 *   - sta_beacon_report_reponse_t report : fixed struct, mac_addr is a 6-byte
 *     memcpy.
 *   - mac_addr_str_t mac_str (char[18])  : bounded to_mac_str.
 * The frame length is validated (len <= min_len rejected), data_len is clamped
 * (0 or > MAX_FRAME_SZ rejected), then report.data = malloc(data_len) and
 * memcpy copies exactly data_len bytes from the frame. No array can be overrun
 * -> SAFE.
 *
 * Scaffolding (NOT under test): to_mac_str / em_beacon_report_publish are
 * stubbed. The ieee80211_mgmt model (common.h) places rrm.variable at
 * IEEE80211_HDRLEN + 1 + sizeof(rrm) == min_len. Driven by the epbr_* globals.
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

typedef struct {
    mac_address_t mac_addr;
    unsigned int data_len;
    unsigned char *data;
    unsigned int ap_index;
    unsigned int num_br_data;
    int sched_handler_id;
    unsigned char dialog_token;
} sta_beacon_report_reponse_t;

/* --- scaffolding stubs driven by epbr_* globals --- */
static char *to_mac_str(mac_address_t mac, mac_addr_str_t key)
{
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}
static int em_beacon_report_publish(void *handle, sta_beacon_report_reponse_t *report)
{
    (void)handle;
    epbr_publish_calls++;
    epbr_last_data_len = report ? report->data_len : 0;
    return epbr_publish_ret;
}

/* ================= VERBATIM from wifi_em.c (static dropped) ================= */
int em_process_beacon_rep(mac_address_t sta_mac, wifi_hal_rrm_report_t *rep, wifi_app_t *app,
    const struct ieee80211_mgmt *mgmt, size_t len, int ap_index)
{
    sta_beacon_report_reponse_t report;
    size_t data_len;
    mac_addr_str_t mac_str;

    memset(&report, 0, sizeof(report));
    memcpy(report.mac_addr, sta_mac, sizeof(mac_address_t));
    report.ap_index = ap_index;
    report.dialog_token = rep->dialog_token;
    report.num_br_data = rep->size;

    size_t min_len = IEEE80211_HDRLEN + 1 + sizeof(mgmt->u.action.u.rrm);
    if (len <= min_len) {
        wifi_util_error_print(WIFI_EM, "%s:%d short beacon report frame len=%zu (min=%zu)\n",
            __func__, __LINE__, len, min_len);
        return -1;
    }

    data_len = len - min_len;
    if (data_len == 0 || data_len > MAX_FRAME_SZ) {
        wifi_util_error_print(WIFI_EM, "%s:%d invalid beacon report data_len=%zu (max=%d)\n",
            __func__, __LINE__, data_len, MAX_FRAME_SZ);
        return -1;
    }
    report.data = (unsigned char *)malloc(data_len);
    if (report.data == NULL) {
        wifi_util_error_print(WIFI_EM,
            "%s:%d failed to allocate %zu bytes for beacon report data\n", __func__, __LINE__,
            data_len);
        return -1;
    }
    report.data_len = data_len;
    memcpy(report.data, mgmt->u.action.u.rrm.variable, data_len);

    to_mac_str(sta_mac, mac_str);
    wifi_util_dbg_print(WIFI_EM,
        "%s:%d forwarding beacon report: sta=%s ap_index=%d num_reports=%zu data_len=%u\n",
        __func__, __LINE__, mac_str, ap_index, rep->size, report.data_len);

    int rc = em_beacon_report_publish(&app->ctrl->handle, &report);
    free(report.data);
    return rc;
}
