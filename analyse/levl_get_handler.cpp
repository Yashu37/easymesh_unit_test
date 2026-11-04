/*
 * HANDLER: levl_get_handler
 *
 * Copied VERBATIM from OneWifi source/apps/levl/wifi_levl.c (only change: the two
 * strncpy dest args get a (char *) cast, needed to compile the C source as C++).
 * Local arrays:
 *   - char parameter[MAX_EVENT_NAME_SIZE=200] : sscanf "%199s" -> at most 199
 *     chars + NUL = 200 -> fits exactly, SAFE. (If event_name lacks the
 *     "Device.WiFi.X_RDK_CSI_LEVL." prefix sscanf writes nothing and
 *     `parameter` stays uninitialised -- see the no_prefix case.)
 *   - char mac_string[18]  : memset 18 + to_mac_str (17 chars + NUL) -> SAFE;
 *     malloc(strlen+1) + strncpy(str_len) matches -> SAFE.
 *   - char buff[32]        : snprintf(sizeof) of " " -> SAFE.
 *
 * Scaffolding (NOT under test): get_wifictrl_obj / get_app_by_inst return the
 * lgh_* buffers (or NULL per case); malloc is redirected to a failing wrapper
 * when the case asks; to_mac_str is local; the bus types are local models.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "common.h"

#define WIFI_APPS 0
#define WIFI_CTRL 0
#ifndef wifi_util_dbg_print
#define wifi_util_dbg_print(m, ...) do {} while (0)
#endif
#define wifi_util_error_print(m, ...) do {} while (0)
#define wifi_app_inst_levl 5
#define MAX_LEVL_CSI_CLIENTS 5
#define DEFAULT_SOUNDING_DURATION_MS 2000

typedef enum { bus_error_success = 0, bus_error_general = 1, bus_error_invalid_input = 2, bus_error_out_of_resources = 3 } bus_error_t;
typedef enum { bus_data_type_string = 3, bus_data_type_uint32 = 7 } raw_data_type_t;
typedef struct { int data_type; union { uint32_t u32; void *bytes; } raw_data; size_t raw_data_len; } raw_data_t;
typedef struct { int unused; } bus_user_data_t;

static char *to_mac_str(mac_address_t mac, mac_addr_str_t key)
{
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}
static wifi_ctrl_t *get_wifictrl_obj(void) { return lgh_null_ctrl ? NULL : (wifi_ctrl_t *)lgh_ctrl_buf; }
static wifi_app_t *get_app_by_inst(wifi_apps_mgr_t *m, int inst) { (void)m; (void)inst; return lgh_null_app ? NULL : (wifi_app_t *)lgh_app_buf; }
static void *lgh_malloc(size_t n) { return lgh_malloc_fail ? NULL : malloc(n); }
#define malloc(n) lgh_malloc(n)

/* ================= VERBATIM from wifi_levl.c ================= */
bus_error_t levl_get_handler(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    (void)user_data;
    bus_error_t ret = bus_error_success;
    char const* name = event_name;
    int max_value = 0, duration = 0;
    char parameter[MAX_EVENT_NAME_SIZE];
    wifi_app_t *wifi_app =  NULL;
    wifi_apps_mgr_t *apps_mgr = NULL;
    mac_address_t null_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

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
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return bus_error_general;
    }

    if (name == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d property name is not found\r\n",__FUNCTION__, __LINE__);
        return bus_error_invalid_input;
    }

    wifi_util_dbg_print(WIFI_CTRL, "%s(): %s\n", __FUNCTION__, name);
    sscanf(name, "Device.WiFi.X_RDK_CSI_LEVL.%199s", parameter);

    if (strcmp(parameter, "clientMac") == 0) {
        char mac_string[18];
        memset(mac_string, 0, 18);
        to_mac_str(null_mac, mac_string);

        uint32_t str_len = strlen(mac_string) + 1;
        p_data->data_type = bus_data_type_string;
        p_data->raw_data.bytes = malloc(str_len);
        if (p_data->raw_data.bytes == NULL) {
            wifi_util_error_print(WIFI_APPS,"%s:%d memory allocation is failed:%d\r\n",__func__,
                __LINE__, str_len);
            return bus_error_out_of_resources;
        }
        strncpy((char *)p_data->raw_data.bytes, mac_string, str_len);
        p_data->raw_data_len = str_len;

    } else if(strcmp(parameter, "maxNumberCSIClients") == 0) {
        if (wifi_app->data.u.levl.max_num_csi_clients == 0) {
            max_value = MAX_LEVL_CSI_CLIENTS;
        } else {
            max_value = wifi_app->data.u.levl.max_num_csi_clients;
        }

        p_data->data_type = bus_data_type_uint32;
        p_data->raw_data.u32 = max_value;
        p_data->raw_data_len = sizeof(max_value);

    } else if(strcmp(parameter, "Duration") == 0) {
        if (wifi_app->data.u.levl.sounding_duration == 0) {
            duration = DEFAULT_SOUNDING_DURATION_MS;
        } else {
            duration = wifi_app->data.u.levl.sounding_duration;
        }

        p_data->data_type = bus_data_type_uint32;
        p_data->raw_data.u32 = duration;
        p_data->raw_data_len = sizeof(duration);

    } else if (strcmp(parameter, "clientMacData") == 0) {
        char buff[32] = {0};
        snprintf(buff, sizeof(buff), " ");

        uint32_t str_len = strlen(buff) + 1;
        p_data->data_type = bus_data_type_string;
        p_data->raw_data.bytes = malloc(str_len);
        if (p_data->raw_data.bytes == NULL) {
            wifi_util_error_print(WIFI_APPS,"%s:%d memory allocation is failed:%d\r\n",__func__,
                __LINE__, str_len);
            return bus_error_out_of_resources;
        }
        strncpy((char *)p_data->raw_data.bytes, buff, str_len);
        p_data->raw_data_len = str_len;
    }
    return ret;
}
