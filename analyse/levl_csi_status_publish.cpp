/*
 * HANDLER: levl_csi_status_publish
 *
 * Copied VERBATIM from OneWifi source/apps/levl/wifi_levl.c (only "static"
 * dropped). Local arrays:
 *   - char eventName[MAX_EVENT_NAME_SIZE]  : snprintf-bounded (fixed event string);
 *   - char eventValue[50]                  : snprintf(sizeof) -- "<17-char mac>;<status>"
 *                                            is at most 28 bytes;
 *   - mac_addr_str_t mac_str               : filled by to_mac_str (17 chars + NUL).
 * Every write is bounded -> SAFE.
 *
 * Scaffolding (NOT under test): to_mac_str / get_bus_descriptor (publish
 * recorder) and the bus types are local models.
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
#define wifi_util_dbg_print(m, ...) do {} while (0)
#endif
#define wifi_util_error_print(m, ...) do {} while (0)
#define WIFI_LEVL_CSI_STATUS "Device.WiFi.X_RDK_CSI_LEVL.soundingStatus"

typedef enum { lcsp_bus_error_success = 0, lcsp_bus_error_general = 1 } bus_error_t;
#define bus_error_success lcsp_bus_error_success
typedef enum { bus_data_type_string = 3 } raw_data_type_t;
typedef struct { int data_type; struct { void *bytes; } raw_data; size_t raw_data_len; } raw_data_t;
typedef struct { bus_error_t (*bus_event_publish_fn)(void *handle, const char *name, raw_data_t *data); } wifi_bus_desc_t;

static char *to_mac_str(mac_address_t mac, mac_addr_str_t key)
{
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}
static bus_error_t lcsp_publish(void *handle, const char *name, raw_data_t *data)
{
    (void)handle;
    snprintf(lcsp_pub_name, sizeof(lcsp_pub_name), "%s", name ? name : "");
    snprintf(lcsp_pub_value, sizeof(lcsp_pub_value), "%s", data && data->raw_data.bytes ? (char *)data->raw_data.bytes : "");
    lcsp_publish_calls++;
    return lcsp_publish_fail ? lcsp_bus_error_general : bus_error_success;
}
static wifi_bus_desc_t lcsp_desc = { lcsp_publish };
static wifi_bus_desc_t *get_bus_descriptor(void) { return &lcsp_desc; }

/* ================= VERBATIM from wifi_levl.c (static dropped) ================= */
int levl_csi_status_publish(bus_handle_t *handle, mac_addr_t mac_addr, unsigned int status)
{
    char eventName[MAX_EVENT_NAME_SIZE];
    char eventValue[50];
    mac_addr_str_t mac_str = { 0 };
    int rc;
    raw_data_t data;
    memset(&data, 0, sizeof(raw_data_t));

    snprintf(eventName, MAX_EVENT_NAME_SIZE, "%s", WIFI_LEVL_CSI_STATUS);
    snprintf(eventValue, sizeof(eventValue), "%s;%d", to_mac_str(mac_addr, mac_str), status);

    data.data_type = bus_data_type_string;
    data.raw_data.bytes = (void *)eventValue;
    data.raw_data_len = (strlen(eventValue) + 1);

    rc = get_bus_descriptor()->bus_event_publish_fn(handle, eventName, &data);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: bus_event_publish_fn Event failed %d\n", __func__, __LINE__, rc);
        return RETURN_ERR;
    } else {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d: bus_event_publish_fn Event for %s %s\n", __func__, __LINE__, eventName, eventValue);
    }

    return RETURN_OK;
}
