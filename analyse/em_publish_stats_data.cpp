/*
 * HANDLER: em_publish_stats_data
 *
 * Copied VERBATIM from OneWifi source/apps/em/wifi_em.c (only "static"
 * dropped). Local array:
 *   - char eventName[MAX_EVENT_NAME_SIZE] (200) : written by
 *     snprintf(eventName, sizeof(eventName), "Device.WiFi.EM.ChannelScanReport")
 *     -- a fixed ~33-char literal, bounded by sizeof. SAFE.
 *
 * Scaffolding (NOT under test): get_wifictrl_obj / webconfig_encode /
 * get_app_by_inst / get_bus_descriptor()->bus_event_publish_fn are stubbed and
 * driven by the eps_* globals. NOTE: the real webconfig_subdoc_data_t.u is a
 * union; here the decoded/encoded fields are modelled as a plain struct so the
 * handler's two heap pointers stay independent and its frees are clean -- the
 * array-bounds behaviour of eventName (the function under test) is unaffected.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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
#define wifi_app_inst_easymesh 0

/* --- local type models --- */
typedef enum { eps_bus_error_success = 0, eps_bus_error_general = 1 } bus_error_t;
#define bus_error_success eps_bus_error_success
typedef enum { webconfig_subdoc_type_em_channel_stats = 7 } webconfig_subdoc_type_t;
typedef enum { webconfig_error_none = 0, webconfig_error_encode = 1 } webconfig_error_t;
typedef enum { bus_data_type_string = 3 } raw_data_type_t;
typedef struct {
    struct { struct { void *stats; } collect_stats; } decoded;
    struct { char *raw; } encoded;
} eps_subdoc_u_t;
typedef struct { eps_subdoc_u_t u; } webconfig_subdoc_data_t;
typedef struct { int data_type; struct { void *bytes; } raw_data; int raw_data_len; } raw_data_t;
typedef struct { bus_error_t (*bus_event_publish_fn)(void *handle, char *name, raw_data_t *data); } wifi_bus_desc_t;

/* --- scaffolding stubs driven by eps_* globals --- */
static wifi_ctrl_t *get_wifictrl_obj(void) { return (wifi_ctrl_t *)eps_ctrl_buf; }
static webconfig_error_t webconfig_encode(void *wc, webconfig_subdoc_data_t *data, webconfig_subdoc_type_t t)
{
    (void)wc; (void)t;
    if (eps_encode_fail) return webconfig_error_encode;
    data->u.encoded.raw = strdup("{\"ChannelScanReport\":\"encoded\"}");
    return webconfig_error_none;
}
static char eps_app_ctrl[256];
static wifi_app_t eps_app_obj;
static wifi_app_t *eps_get_app(wifi_apps_mgr_t *mgr, int inst)
{
    (void)mgr; (void)inst;
    eps_app_obj.ctrl = (decltype(eps_app_obj.ctrl))eps_app_ctrl;
    return &eps_app_obj;
}
#define get_app_by_inst(m, i)  eps_get_app((m), (i))
static bus_error_t eps_publish(void *handle, char *name, raw_data_t *data)
{
    (void)handle; (void)data;
    snprintf(eps_published_event, sizeof(eps_published_event), "%s", name ? name : "(null)");
    eps_publish_calls++;
    return eps_publish_fail ? eps_bus_error_general : bus_error_success;
}
static wifi_bus_desc_t eps_desc = { eps_publish };
static wifi_bus_desc_t *get_bus_descriptor(void) { return &eps_desc; }

/* ================= VERBATIM from wifi_em.c (static dropped) ================= */
int em_publish_stats_data(channel_scan_response_t *scan_response)
{
    webconfig_subdoc_data_t *data;
    bus_error_t status;
    char eventName[MAX_EVENT_NAME_SIZE] = { 0 };
    webconfig_subdoc_type_t subdoc_type;
    time_t response_time;
    raw_data_t rdata;
    wifi_apps_mgr_t *apps_mgr = NULL;
    wifi_app_t *wifi_app = NULL;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    data = (webconfig_subdoc_data_t *)malloc(sizeof(webconfig_subdoc_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d Error in allocation memory\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    memset(data, '\0', sizeof(webconfig_subdoc_data_t));
    data->u.decoded.collect_stats.stats = (struct channel_scan_response_t *)malloc(
        sizeof(channel_scan_response_t));
    if (data->u.decoded.collect_stats.stats == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d Error in allocating memory\n", __func__, __LINE__);
        free(data);
        return RETURN_ERR;
    }

    (void)time(&response_time);

    memcpy(data->u.decoded.collect_stats.stats, scan_response, sizeof(channel_scan_response_t));

    subdoc_type = webconfig_subdoc_type_em_channel_stats;
    snprintf(eventName, sizeof(eventName), "Device.WiFi.EM.ChannelScanReport");

    wifi_util_dbg_print(WIFI_EM, "%s:%d subdoc_type is %d and eventName is %s at %ld\n", __func__,
        __LINE__, subdoc_type, eventName, response_time);

    if (webconfig_encode(&ctrl->webconfig, data, subdoc_type) != webconfig_error_none) {
        wifi_util_error_print(WIFI_EM, "%s:%d Error in encoding channel scan stats\n", __func__,
            __LINE__);
        free(data->u.decoded.collect_stats.stats);
        free(data);
        return RETURN_ERR;
    }

    memset(&rdata, 0, sizeof(raw_data_t));
    rdata.data_type = bus_data_type_string;
    rdata.raw_data.bytes = (void *)data->u.encoded.raw;
    rdata.raw_data_len = strlen(data->u.encoded.raw) + 1;

    apps_mgr = &ctrl->apps_mgr;
    wifi_app = get_app_by_inst(apps_mgr, wifi_app_inst_easymesh);

    status = get_bus_descriptor()->bus_event_publish_fn(&wifi_app->ctrl->handle, eventName, &rdata);

    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_EM, "%s:%d: bus: bus_event_publish_fn Event failed %d\n",
            __func__, __LINE__, status);
        free(data->u.encoded.raw);
        free(data->u.decoded.collect_stats.stats);
        free(data);
        return RETURN_ERR;
    }
    free(data->u.encoded.raw);
    free(data->u.decoded.collect_stats.stats);
    free(data);

    wifi_util_dbg_print(WIFI_EM, "%s:%d Scan results published\n", __func__, __LINE__);

    return RETURN_OK;
}
