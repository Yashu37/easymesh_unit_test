/*
 * HANDLER: em_init
 *
 * Copied VERBATIM from OneWifi source/apps/em/wifi_em.c (already non-static).
 * Local array under test:
 *   bus_data_element_t dataElements[] = { ...12 entries... };
 * It is a fixed, read-only registration table built from an initializer and
 * passed to bus_reg_data_element_fn(..., sizeof(dataElements)/sizeof(elem)).
 * Nothing indexes or writes into it beyond the initializer -> SAFE (same
 * pattern as easyconnect_init).
 *
 * Scaffolding (NOT under test): the bus/app plumbing and the referenced method
 * callbacks are stubbed and driven by the emi_* globals. NO ASan calls here.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
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
#define wifi_util_info_print(m, ...)  do {} while (0)
#define wifi_util_error_print(m, ...) do {} while (0)
#endif
#define ZERO_TABLE 0
/* event-name strings (values don't matter for the test) */
#define WIFI_EM_CHANNEL_SCAN_REQUEST    "Device.WiFi.EM.ChannelScanRequest"
#define WIFI_SET_DISCONN_STEADY_STATE   "Device.WiFi.EM.DisconnSteady"
#define WIFI_SET_DISCONN_SCAN_NONE_STATE "Device.WiFi.EM.DisconnScanNone"
#define WIFI_EM_CHANNEL_SCAN_REPORT     "Device.WiFi.EM.ChannelScanReport"
#define WIFI_EM_BEACON_QUERY            "Device.WiFi.EM.BeaconQuery"
#define WIFI_EM_BEACON_REPORT           "Device.WiFi.EM.BeaconReport"
#define WIFI_EM_STA_LINK_METRICS_REPORT "Device.WiFi.EM.StaLinkMetrics"
#define WIFI_EM_ASSOCIATION_STATUS      "Device.WiFi.EM.AssociationStatus"
#define WIFI_EM_REPORT_CONNECTION_STATUS "Device.WiFi.EM.ConnectionStatus"
#define WIFI_EM_AP_METRICS_REPORT       "Device.WiFi.EM.ApMetricsReport"
#define WIFI_EM_CLIENT_ASSOC_CTRL_REQ   "Device.WiFi.EM.ClientAssocCtrl"
#define WIFI_EM_FAILED_CONNECTION       "Device.WiFi.EM.FailedConnection"

/* --- bus types (local to this TU) --- */
typedef enum { emi_bus_error_success = 0, emi_bus_error_general = 1 } bus_error_t;
#define bus_error_success emi_bus_error_success
typedef enum { bus_element_type_method = 1, bus_element_type_event = 2 } bus_element_type_t;
typedef enum { slow_speed = 0 } bus_speed_t;
typedef enum { bus_data_type_none = 0, bus_data_type_string = 3, bus_data_type_byte = 9, bus_data_type_bytes = 10 } bus_data_type_t;
typedef struct { void *a, *b, *c, *d, *e, *f; } bus_callback_table_t;
typedef struct { bus_data_type_t data_format; bool perm; long mn; long mx; uint32_t nval; char **sval; } data_model_properties_t;
typedef struct { char *full_name; bus_element_type_t type; bus_callback_table_t cb_table; bus_speed_t bus_speed; uint32_t num_of_table_row; data_model_properties_t data_model_prop; } bus_data_element_t;
typedef struct {
    bus_error_t (*bus_open_fn)(void *handle, const char *name);
    bus_error_t (*bus_reg_data_element_fn)(void *handle, bus_data_element_t *elems, int num);
} wifi_bus_desc_t;

/* method callbacks referenced in the table (real ones live elsewhere) */
static bus_error_t start_channel_scan(char *n, void *d) { (void)n; (void)d; return bus_error_success; }
static bus_error_t set_disconn_steady_state(char *n, void *d) { (void)n; (void)d; return bus_error_success; }
static bus_error_t set_disconn_scan_none_state(char *n, void *d) { (void)n; (void)d; return bus_error_success; }
static bus_error_t send_beacon_query(char *n, void *d) { (void)n; (void)d; return bus_error_success; }
static bus_error_t cacr_set_client_acl_rules(char *n, void *d) { (void)n; (void)d; return bus_error_success; }

/* --- scaffolding stubs driven by emi_* globals --- */
static struct { struct { void *client_type_map; } sta_client_type; } client_type_info;
static void *hash_map_create(void) { return (void *)0x1; }
static void ap_report_cache_init(void) { emi_cache_init_calls++; }
static int app_init(wifi_app_t *app, unsigned int f) { (void)app; (void)f; return emi_app_init_ret; }
static bus_error_t emi_open(void *h, const char *n) { (void)h; (void)n; return emi_bus_open_fail ? emi_bus_error_general : bus_error_success; }
static bus_error_t emi_reg(void *h, bus_data_element_t *elems, int num)
{
    (void)h;
    emi_reg_calls++;
    emi_reg_num = num;
    if (num >= 1 && elems[0].full_name) snprintf(emi_elem0_name, sizeof(emi_elem0_name), "%s", elems[0].full_name);
    return emi_bus_reg_fail ? emi_bus_error_general : bus_error_success;
}
static wifi_bus_desc_t emi_desc = { emi_open, emi_reg };
static wifi_bus_desc_t *get_bus_descriptor(void) { return &emi_desc; }

/* ================= VERBATIM from wifi_em.c ================= */
int em_init(wifi_app_t *app, unsigned int create_flag)
{
    int rc = RETURN_OK;
    char *component_name = "WifiEM";
    int num_elements;
    em_config_t *policy_config = &app->data.u.em_data.em_config;

    bus_data_element_t dataElements[] = {
        { WIFI_EM_CHANNEL_SCAN_REQUEST, bus_element_type_method,
            { NULL, (void*)start_channel_scan, NULL, NULL, NULL, NULL}, slow_speed, ZERO_TABLE,
            { bus_data_type_bytes, true, 0, 0, 0, NULL } },
        { WIFI_SET_DISCONN_STEADY_STATE, bus_element_type_method,
            { NULL, (void*)set_disconn_steady_state, NULL, NULL, NULL, NULL}, slow_speed, ZERO_TABLE,
            { bus_data_type_none, true, 0, 0, 0, NULL } },
        { WIFI_SET_DISCONN_SCAN_NONE_STATE, bus_element_type_method,
            { NULL, (void*)set_disconn_scan_none_state, NULL, NULL, NULL, NULL}, slow_speed, ZERO_TABLE,
            { bus_data_type_none, true, 0, 0, 0, NULL } },
        { WIFI_EM_CHANNEL_SCAN_REPORT, bus_element_type_event,
            { NULL, NULL, NULL, NULL, NULL, NULL}, slow_speed, ZERO_TABLE,
            { bus_data_type_bytes, false, 0, 0, 0, NULL } },
        { WIFI_EM_BEACON_QUERY, bus_element_type_method,
            { NULL, (void*)send_beacon_query, NULL, NULL, NULL, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_bytes, true, 0, 0, 0, NULL } },
        { WIFI_EM_BEACON_REPORT, bus_element_type_method,
            { NULL, NULL, NULL, NULL, NULL, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_string, false, 0, 0, 0, NULL } },
        { WIFI_EM_STA_LINK_METRICS_REPORT, bus_element_type_method,
            { NULL, NULL, NULL, NULL, NULL, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_string, false, 0, 0, 0, NULL } },
        { WIFI_EM_ASSOCIATION_STATUS, bus_element_type_method,
            { NULL, NULL, NULL, NULL, NULL, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_byte, false, 0, 0, 0, NULL } } ,
        { WIFI_EM_REPORT_CONNECTION_STATUS, bus_element_type_method,
            { NULL, NULL, NULL, NULL, NULL, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_bytes, false, 0, 0, 0, NULL } },
        { WIFI_EM_AP_METRICS_REPORT, bus_element_type_method,
            { NULL, NULL, NULL, NULL, NULL, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_string, false, 0, 0, 0, NULL } },
        { WIFI_EM_CLIENT_ASSOC_CTRL_REQ, bus_element_type_method,
            { NULL, (void*)cacr_set_client_acl_rules, NULL, NULL, NULL, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_string, true, 0, 0, 0, NULL } },
        { WIFI_EM_FAILED_CONNECTION, bus_element_type_event,
            { NULL, NULL, NULL, NULL, NULL, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_string, false, 0, 0, 0, NULL } }
    };

    policy_config->btm_steering_dslw_policy.sta_count = 0;
    policy_config->local_steering_dslw_policy.sta_count = 0;
    policy_config->radio_metrics_policies.radio_count = 0;

    if (app_init(app, create_flag) != 0) {
        return RETURN_ERR;
    }

    client_type_info.sta_client_type.client_type_map = hash_map_create();

    ap_report_cache_init();

    rc = get_bus_descriptor()->bus_open_fn(&app->handle, component_name);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_EM,
            "%s:%d bus: bus_open_fn open failed for component:%s, rc:%d\n", __func__, __LINE__,
            component_name, rc);
        return RETURN_ERR;
    }

    num_elements = (sizeof(dataElements) / sizeof(bus_data_element_t));

    rc = get_bus_descriptor()->bus_reg_data_element_fn(&app->ctrl->handle, dataElements,
        num_elements);
    if (rc != bus_error_success) {
        wifi_util_dbg_print(WIFI_EM, "%s:%d bus_reg_data_element_fn failed, rc:%d\n", __func__,
            __LINE__, rc);
    } else {
        wifi_util_info_print(WIFI_EM, "%s:%d Apps bus_regDataElement success\n", __func__,
            __LINE__);
    }

    wifi_util_info_print(WIFI_EM, "%s:%d: Init em app %s\n", __func__, __LINE__,
        rc ? "failure" : "success");

    return rc;
}
