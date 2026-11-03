/*
 * HANDLER: em_handle_connection_status
 *
 * Copied VERBATIM from OneWifi source/apps/em/wifi_em.c (only "static"
 * dropped). Local arrays:
 *   - mac_addr_str_t sta_mac_str, bssid_str (char[18]) : bounded to_mac_str.
 * The published payload is malloc(sizeof(*conn_status)) with a memcpy of
 * exactly that size. NULL app/data rejected. No array can be overrun -> SAFE.
 *
 * Scaffolding (NOT under test): to_mac_str /
 * get_bus_descriptor()->bus_event_publish_fn are stubbed and driven by the
 * ehcs_* globals.
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
#define wifi_util_info_print(m, ...)  do {} while (0)
#define wifi_util_error_print(m, ...) do {} while (0)
#endif
#define WIFI_EM_REPORT_CONNECTION_STATUS "Device.WiFi.EM.ConnectionStatus"

/* --- local type models --- */
typedef enum { ehcs_bus_error_success = 0, ehcs_bus_error_general = 1 } bus_error_t;
#define bus_error_success ehcs_bus_error_success
typedef enum { bus_data_type_bytes = 11 } raw_data_type_t;
typedef struct { int data_type; struct { void *bytes; } raw_data; size_t raw_data_len; } raw_data_t;
typedef struct { bus_error_t (*bus_event_publish_fn)(void *handle, const char *name, raw_data_t *data); } wifi_bus_desc_t;

/* --- scaffolding stubs driven by ehcs_* globals --- */
static char *to_mac_str(mac_address_t mac, mac_addr_str_t key)
{
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}
static bus_error_t ehcs_publish(void *handle, const char *name, raw_data_t *data)
{
    (void)handle;
    snprintf(ehcs_published_event, sizeof(ehcs_published_event), "%s", name ? name : "");
    ehcs_last_len = data ? (int)data->raw_data_len : -1;
    ehcs_publish_calls++;
    return ehcs_publish_fail ? ehcs_bus_error_general : bus_error_success;
}
static wifi_bus_desc_t ehcs_desc = { ehcs_publish };
static wifi_bus_desc_t *get_bus_descriptor(void) { return &ehcs_desc; }

/* ================= VERBATIM from wifi_em.c (static dropped) ================= */
int em_handle_connection_status(wifi_app_t *app, void *data)
{
    const em_connection_status_event_t *conn_status = (const em_connection_status_event_t *)data;
    raw_data_t rdata = { 0 };
    mac_addr_str_t sta_mac_str, bssid_str;
    bus_error_t rc;

    if ((app == NULL) || (conn_status == NULL)) {
        return RETURN_ERR;
    }

    rdata.raw_data.bytes = malloc(sizeof(*conn_status));
    if (rdata.raw_data.bytes == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d: Could not allocate connection status data\n",
            __func__, __LINE__);
        return RETURN_ERR;
    }

    wifi_util_info_print(WIFI_EM,
        "%s:%d: Connection Status STA=%s BSSID=%s Status=%u Reason Present=%d Reason=%u\n",
        __func__, __LINE__, to_mac_str(conn_status->sta_mac, sta_mac_str),
        to_mac_str(conn_status->bssid, bssid_str), conn_status->status_code,
        conn_status->reason_code_present, conn_status->reason_code);

    rdata.data_type = bus_data_type_bytes;
    memcpy(rdata.raw_data.bytes, conn_status, sizeof(*conn_status));
    rdata.raw_data_len = sizeof(*conn_status);
    rc = get_bus_descriptor()->bus_event_publish_fn(&app->ctrl->handle,
        WIFI_EM_REPORT_CONNECTION_STATUS, &rdata);
    free(rdata.raw_data.bytes);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_EM, "%s:%d: Connection Status publish failed %d\n", __func__,
            __LINE__, rc);
        return RETURN_ERR;
    }

    return RETURN_OK;
}
