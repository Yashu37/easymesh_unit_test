/*
 * HANDLER: radio_temperature_response
 *
 * Copied VERBATIM from OneWifi source/apps/levl/wifi_levl.c (no changes).
 * Local array:
 *   - char eventName[64] : snprintf(sizeof) of "Device.WiFi.Events.Radio.%u.Temperature"
 *     (at most 47 bytes) -> bounded, SAFE.
 * Reads from the caller's stat_pointer: the loop never advances
 * temperature_stats, so every iteration re-reads element 0 -> no over-read
 * (functional note only: it publishes the first radio's value stat_array_size
 * times).
 *
 * Scaffolding (NOT under test): get_wifictrl_obj / get_app_by_inst return the
 * lrt_* buffers (or NULL per case); get_bus_descriptor returns a publish
 * recorder; the bus types are local models.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "common.h"

#define WIFI_APPS 0
#ifndef RETURN_OK
#define RETURN_OK  0
#endif
#ifndef RETURN_ERR
#define RETURN_ERR (-1)
#endif
#ifndef wifi_util_dbg_print
#define wifi_util_dbg_print(m, ...) do {} while (0)
#endif
#define wifi_util_error_print(m, ...) do {} while (0)
#define wifi_app_inst_levl 5

typedef enum { bus_error_success = 0, bus_error_general = 1 } bus_error_t;
typedef enum { bus_data_type_uint32 = 7 } raw_data_type_t;
typedef struct { int data_type; union { uint32_t u32; void *bytes; } raw_data; size_t raw_data_len; } raw_data_t;
typedef struct { bus_error_t (*bus_event_publish_fn)(void *handle, const char *name, raw_data_t *data); } wifi_bus_desc_t;

static wifi_ctrl_t *get_wifictrl_obj(void) { return lrt_null_ctrl ? NULL : (wifi_ctrl_t *)lrt_ctrl_buf; }
static wifi_app_t *get_app_by_inst(wifi_apps_mgr_t *m, int inst) { (void)m; (void)inst; return lrt_null_app ? NULL : (wifi_app_t *)lrt_app_buf; }
static bus_error_t lrt_publish(void *handle, const char *name, raw_data_t *data)
{
    (void)handle;
    snprintf(lrt_pub_name, sizeof(lrt_pub_name), "%s", name ? name : "");
    lrt_pub_value = data ? data->raw_data.u32 : 0;
    lrt_pub_type = data ? data->data_type : -1;
    lrt_pub_calls++;
    return lrt_publish_fail ? bus_error_general : bus_error_success;
}
static wifi_bus_desc_t lrt_desc = { lrt_publish };
static wifi_bus_desc_t *get_bus_descriptor(void) { return &lrt_desc; }

/* ================= VERBATIM from wifi_levl.c ================= */
int radio_temperature_response(wifi_provider_response_t *provider_response)
{
    wifi_app_t *wifi_app =  NULL;
    wifi_apps_mgr_t *apps_mgr = NULL;
    char eventName[64] = {0};
    unsigned int radio_index = provider_response->args.radio_index;
    int rc = bus_error_success;
    raw_data_t data;
    memset(&data, 0, sizeof(raw_data_t));

    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return bus_error_general;
    }

    apps_mgr = &ctrl->apps_mgr;
    if (apps_mgr == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return bus_error_general;
    }

    wifi_app = get_app_by_inst(apps_mgr, wifi_app_inst_levl);
    if (wifi_app == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return RETURN_ERR;
    }

    radio_data_t *temperature_stats = (radio_data_t*) provider_response->stat_pointer;
    for(unsigned int count = 0; count < provider_response->stat_array_size; count++) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d Radio temperature for radio%d is %u\n", __func__, __LINE__, radio_index, temperature_stats->radio_Temperature);
        snprintf(eventName, sizeof(eventName), "Device.WiFi.Events.Radio.%u.Temperature", radio_index+1);

        data.data_type = bus_data_type_uint32;
        data.raw_data.u32 = (uint32_t)temperature_stats->radio_Temperature;

        rc = get_bus_descriptor()->bus_event_publish_fn(&wifi_app->handle, eventName, &data);
        if (rc != bus_error_success) {
            wifi_util_error_print(WIFI_APPS, "%s:%d: bus_event_publish_fn Event failed %d\n", __func__, __LINE__, rc);
            return RETURN_ERR;
        } else {
            wifi_util_dbg_print(WIFI_APPS, "%s:%d: bus_event_publish_fn Event for %s\n", __func__, __LINE__, eventName);
        }
    }
    return RETURN_OK;
}
