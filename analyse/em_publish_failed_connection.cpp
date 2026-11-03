/*
 * HANDLER: em_publish_failed_connection
 *
 * Copied VERBATIM from OneWifi source/apps/em/wifi_em.c (only "static"
 * dropped). Local arrays:
 *   - mac_addr_str_t bssid_str, sta_str (char[18]) : bounded to_mac_str.
 *   - char json_buf[EM_FAILED_CONN_JSON_MAX] (128)  : written by a single
 *     snprintf bounded by sizeof(json_buf), with an explicit
 *     "n >= sizeof(json_buf)" truncation check that returns RETURN_ERR.
 * No array can be overrun -> SAFE.
 *
 * Scaffolding (NOT under test): get_wifictrl_obj / to_mac_str /
 * get_bus_descriptor()->bus_event_publish_fn are stubbed and driven by the
 * pfc_* globals.
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
#define wifi_util_error_print(m, ...) do {} while (0)
#endif
#define EM_FAILED_CONN_JSON_MAX 128
#define WIFI_EM_FAILED_CONNECTION "Device.WiFi.EM.FailedConnection"

/* --- local type models --- */
typedef enum { pfc_bus_error_success = 0, pfc_bus_error_general = 1 } bus_error_t;
#define bus_error_success pfc_bus_error_success
typedef enum { bus_data_type_string = 3 } raw_data_type_t;
typedef struct { int data_type; struct { void *bytes; } raw_data; size_t raw_data_len; } raw_data_t;
typedef struct { bus_error_t (*bus_event_publish_fn)(void *handle, const char *name, raw_data_t *data); } wifi_bus_desc_t;

/* --- scaffolding stubs driven by pfc_* globals --- */
static wifi_ctrl_t *get_wifictrl_obj(void) { return (wifi_ctrl_t *)pfc_ctrl_buf; }
static char *to_mac_str(mac_address_t mac, mac_addr_str_t key)
{
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}
static bus_error_t pfc_publish(void *handle, const char *name, raw_data_t *data)
{
    (void)handle;
    snprintf(pfc_published_json, sizeof(pfc_published_json), "%s", data && data->raw_data.bytes ? (char *)data->raw_data.bytes : "");
    snprintf(pfc_published_event, sizeof(pfc_published_event), "%s", name ? name : "");
    pfc_publish_calls++;
    return pfc_publish_fail ? pfc_bus_error_general : bus_error_success;
}
static wifi_bus_desc_t pfc_desc = { pfc_publish };
static wifi_bus_desc_t *get_bus_descriptor(void) { return &pfc_desc; }

/* ================= VERBATIM from wifi_em.c (static dropped) ================= */
int em_publish_failed_connection(const wifi_em_failed_conn_t *fc)
{
    wifi_ctrl_t *wifi_ctrl = get_wifictrl_obj();
    raw_data_t rdata = {0};
    mac_addr_str_t bssid_str, sta_str;
    char json_buf[EM_FAILED_CONN_JSON_MAX];
    int n;
    bus_error_t rc;

    to_mac_str(fc->bssid,   bssid_str);
    to_mac_str(fc->sta_mac, sta_str);

    n = snprintf(json_buf, sizeof(json_buf),
        "{\"bssid\":\"%s\",\"sta_mac\":\"%s\",\"status\":%u,\"reason\":%u}",
        bssid_str, sta_str, (unsigned int)fc->status, (unsigned int)fc->reason);
    if (n < 0) {
        wifi_util_error_print(WIFI_EM, "%s:%d: snprintf failed (n=%d)\n",
            __func__, __LINE__, n);
        return RETURN_ERR;
    } else if (n >= (int)sizeof(json_buf)) {
        wifi_util_error_print(WIFI_EM, "%s:%d: JSON truncated (n=%d, max=%zu)\n",
            __func__, __LINE__, n, sizeof(json_buf));
        return RETURN_ERR;
    }

    rdata.data_type = bus_data_type_string;
    rdata.raw_data.bytes = (void *)json_buf;
    rdata.raw_data_len = (size_t)n + 1;

    rc = get_bus_descriptor()->bus_event_publish_fn(&wifi_ctrl->handle,
        WIFI_EM_FAILED_CONNECTION, &rdata);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_EM, "%s:%d: bus_event_publish_fn failed rc=%d\n",
            __func__, __LINE__, rc);
        return RETURN_ERR;
    }

    return RETURN_OK;
}
