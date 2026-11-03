/*
 * HANDLER: em_handle_sta_conn_status
 *
 * Copied VERBATIM from OneWifi source/apps/em/wifi_em.c (only "static"
 * dropped). Local array:
 *   - char path[256] : written by snprintf(path, sizeof(path),
 *     WIFI_EM_ASSOCIATION_STATUS) -- a fixed event-name literal, bounded. SAFE.
 *
 * NOTE: the upstream function has no return statement on the success path
 * (falls off the end of an int-returning function). That is a latent
 * missing-return, not an array-bounds issue; it is kept verbatim and the
 * runner does not read the return value on the success path.
 *
 * Scaffolding (NOT under test): get_wifictrl_obj /
 * get_bus_descriptor()->bus_event_publish_fn are stubbed and driven by the
 * hscs_* globals.
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
#define WIFI_APPS 0
#ifndef wifi_util_dbg_print
#define wifi_util_error_print(m, ...) do {} while (0)
#endif
#define WIFI_EM_ASSOCIATION_STATUS "Device.WiFi.EM.AssociationStatus"

/* --- local type models --- */
typedef enum { hscs_bus_error_success = 0, hscs_bus_error_general = 1 } bus_error_t;
typedef enum { bus_data_type_bytes = 11 } raw_data_type_t;
typedef struct { int data_type; struct { void *bytes; } raw_data; size_t raw_data_len; } raw_data_t;
typedef struct { bus_error_t (*bus_event_publish_fn)(void *handle, const char *name, raw_data_t *data); } wifi_bus_desc_t;

/* --- scaffolding stubs driven by hscs_* globals --- */
static wifi_ctrl_t *get_wifictrl_obj(void) { return (wifi_ctrl_t *)hscs_ctrl_buf; }
static bus_error_t hscs_publish(void *handle, const char *name, raw_data_t *data)
{
    (void)handle; (void)data;
    snprintf(hscs_published_event, sizeof(hscs_published_event), "%s", name ? name : "");
    hscs_publish_calls++;
    hscs_last_len = data ? (int)data->raw_data_len : -1;
    return hscs_bus_error_success;
}
static wifi_bus_desc_t hscs_desc = { hscs_publish };
static wifi_bus_desc_t *get_bus_descriptor(void) { return &hscs_desc; }

/* ================= VERBATIM from wifi_em.c (static dropped) ================= */
int em_handle_sta_conn_status(wifi_app_t *app, void *data)
{
    rdk_sta_data_t *sta_data = (rdk_sta_data_t *)data;
    if (sta_data == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: NULL STA data!\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    // Publish the whole rdk_sta_data_t
    wifi_ctrl_t *wifi_ctrl = get_wifictrl_obj();
    raw_data_t rdata = {0};
    rdata.raw_data.bytes = malloc(sizeof(rdk_sta_data_t));
    if (rdata.raw_data.bytes == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: Could not allocate for rdk_sta_data_t\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    rdata.data_type = bus_data_type_bytes;
    memcpy(rdata.raw_data.bytes, sta_data, sizeof(rdk_sta_data_t));
    rdata.raw_data_len = sizeof(rdk_sta_data_t);
    char path[256] = {0};
    snprintf(path, sizeof(path), WIFI_EM_ASSOCIATION_STATUS);
    get_bus_descriptor()->bus_event_publish_fn(&wifi_ctrl->handle, path, &rdata);
    free(rdata.raw_data.bytes);
    return RETURN_OK;   /* NOTE: upstream omits this return (falls off the end of an int function) */
}
