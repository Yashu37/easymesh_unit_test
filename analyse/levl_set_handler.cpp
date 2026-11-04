/*
 * HANDLER: levl_set_handler
 *
 * Copied VERBATIM from OneWifi source/apps/levl/wifi_levl.c (no changes). Local array:
 *   - char parameter[MAX_EVENT_NAME_SIZE=200] : sscanf "%199s" -> at most 199
 *     chars + NUL = 200 -> fits exactly, SAFE. (A name without the
 *     "Device.WiFi.X_RDK_CSI_LEVL." prefix leaves it uninitialised, as in
 *     levl_get_handler.)
 * Writes into the malloc'd levl_config_t: clientMac[6] is filled by
 * str_to_mac_bytes / string_mac_to_uint8_mac (6 bytes each) -> SAFE.
 * Reads the caller's string (p_data->raw_data.bytes) via those helpers and
 * strdup + strtok_r -- the runner hands them an exact-size string with a
 * poisoned tail. ptr = strdup(pTmp) is not NULL-checked (OOM only).
 *
 * Scaffolding (NOT under test): str_to_mac_bytes and string_mac_to_uint8_mac
 * are copied VERBATIM from source/utils/wifi_util.c (they parse the caller's
 * string); update_levl_config_from_levl_config and
 * push_levl_data_dml_to_ctrl_queue are recording stubs; malloc is redirected
 * to a failing wrapper when the case asks; the bus types are local models.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "common.h"

#define WIFI_APPS 0
#define WIFI_CTRL 0
#define WIFI_WEBCONFIG 0
#ifndef wifi_util_dbg_print
#define wifi_util_dbg_print(m, ...) do {} while (0)
#endif
#define wifi_util_error_print(m, ...) do {} while (0)
#define MAX_LEVL_CSI_CLIENTS 5
#define DEFAULT_SOUNDING_DURATION_MS 2000
#define MIN_LEVL_PUBLISH_INTERVAL_MS 100
#define MIN_LEVL_SOUNDING_DURATION_MS 1000
#ifndef MIN_MAC_LEN
#define MIN_MAC_LEN 12
#endif

typedef enum { bus_error_success = 0, bus_error_general = 1, bus_error_invalid_input = 2, bus_error_out_of_resources = 3 } bus_error_t;
typedef enum { bus_data_type_string = 3, bus_data_type_uint32 = 7 } raw_data_type_t;
typedef struct { int data_type; union { uint32_t u32; void *bytes; } raw_data; size_t raw_data_len; } raw_data_t;
typedef struct { int unused; } bus_user_data_t;

/* ---- VERBATIM from source/utils/wifi_util.c ---- */
void string_mac_to_uint8_mac(uint8_t *mac, char *s_mac)
{

    if((mac == NULL) || (s_mac == NULL))
    {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d:parameters is NULL\n", __func__, __LINE__);
        return;
    }
    sscanf(s_mac, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", &mac[0], &mac[1], &mac[2],&mac[3], &mac[4], &mac[5]);
}
void str_to_mac_bytes (char *key, mac_addr_t bmac) {
    unsigned int mac[6];

    if (strlen(key) == 0) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Input mac address is empty.\n", __func__, __LINE__);
        return;
    }

    if(strlen(key) > MIN_MAC_LEN)
        sscanf(key, "%02x:%02x:%02x:%02x:%02x:%02x",
                &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    else
        sscanf(key, "%02x%02x%02x%02x%02x%02x",
                &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    bmac[0] = mac[0]; bmac[1] = mac[1]; bmac[2] = mac[2];
    bmac[3] = mac[3]; bmac[4] = mac[4]; bmac[5] = mac[5];

}

static void update_levl_config_from_levl_config(levl_config_t *levl) { (void)levl; /* app values are 0 here */ }
static int push_levl_data_dml_to_ctrl_queue(levl_config_t **levl)
{
    lsh_push_calls++;
    memcpy(&lsh_pushed, *levl, sizeof(levl_config_t));
    return 0;
}
static void *lsh_malloc(size_t n) { return lsh_malloc_fail ? NULL : malloc(n); }
#define malloc(n) lsh_malloc(n)

/* ================= VERBATIM from wifi_levl.c ================= */
bus_error_t levl_set_handler(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    (void)user_data;
    char const* name = event_name;
    unsigned int levl_sounding_duration = 0;
    char const* pTmp = NULL;
    char parameter[MAX_EVENT_NAME_SIZE];
    unsigned int csinum = 0;
    int interval = 0, duration = 0;
    levl_config_t *levl = NULL;

    if (!name) {
        wifi_util_error_print(WIFI_CTRL, "%s %d: invalid bus property name %s\n", __FUNCTION__, __LINE__, name);
        return bus_error_invalid_input;
    }
    levl = (levl_config_t *)malloc(sizeof(levl_config_t));
    if (levl == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s %d: NULL Pointer\n", __func__, __LINE__);
        return bus_error_general;
    }
    memset(levl, 0, sizeof(levl_config_t));
    update_levl_config_from_levl_config(levl);

    wifi_util_dbg_print(WIFI_CTRL, "%s(): %s\n", __FUNCTION__, name);

    sscanf(name, "Device.WiFi.X_RDK_CSI_LEVL.%199s", parameter);

    if (strcmp(parameter, "clientMac") == 0) {
        if (p_data->data_type != bus_data_type_string) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d-%s wrong bus data_type:%x\n", __func__, __LINE__, name, p_data->data_type);
            if (levl != NULL) {
                free(levl);
            }
            return bus_error_invalid_input;
        }

        pTmp = (char *)p_data->raw_data.bytes;
        if (pTmp == NULL) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d-%s wrong bus data:%02x\n", __func__, __LINE__, name, p_data->data_type);
            if (levl != NULL) {
                free(levl);
            }
            return bus_error_invalid_input;
        }

        str_to_mac_bytes((char *)pTmp, levl->clientMac);

    } else if(strcmp(parameter, "maxNumberCSIClients") == 0) {
        if (p_data->data_type != bus_data_type_uint32) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d-%s wrong bus data_type:%x\n", __func__, __LINE__, name, p_data->data_type);
            if (levl != NULL) {
                free(levl);
            }
            return bus_error_invalid_input;
        }

        csinum = p_data->raw_data.u32;

        if (csinum > MAX_LEVL_CSI_CLIENTS) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d Exceeds MAX_LEVL_CSI_CLIENTS\n", __func__, __LINE__);
            if (levl != NULL) {
                free(levl);
            }
            return bus_error_invalid_input;
        }
        levl->max_num_csi_clients = csinum;
    } else if (strcmp(parameter, "Duration") == 0) {

        if (p_data->data_type != bus_data_type_uint32) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d-%s wrong bus data_type:%x\n", __func__, __LINE__, name, p_data->data_type);
            if (levl != NULL) {
                free(levl);
            }
            return bus_error_invalid_input;
        }

        levl_sounding_duration = p_data->raw_data.u32;

        if (levl_sounding_duration == 0) {
            levl->levl_sounding_duration = DEFAULT_SOUNDING_DURATION_MS;
        } else {
            levl->levl_sounding_duration = levl_sounding_duration;
        }
    } else if (strcmp(parameter, "clientMacData") == 0) {
        char *mac_data = NULL, *saveptr = NULL, *ptr = NULL;
        if (p_data->data_type != bus_data_type_string) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d-%s wrong bus data_type:%x\n", __func__, __LINE__, name, p_data->data_type);
            if (levl != NULL) {
                free(levl);
            }
            return bus_error_invalid_input;
        }

        pTmp = (char *)p_data->raw_data.bytes;
        if (pTmp == NULL) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d-%s wrong bus data:%x\n", __func__, __LINE__, name, p_data->data_type);
            if (levl != NULL) {
                free(levl);
            }
            return bus_error_invalid_input;
        }

        ptr = strdup(pTmp);
        mac_data = strtok_r(ptr, ";", &saveptr);
        if (mac_data != NULL)
            string_mac_to_uint8_mac(levl->clientMac, mac_data);

        mac_data = strtok_r(NULL, ";", &saveptr);
        if (mac_data != NULL) {
            interval = atoi(mac_data);
            if (interval < MIN_LEVL_PUBLISH_INTERVAL_MS) {
                wifi_util_error_print(WIFI_APPS, "%s:%d The publish interval should be at least %dms\n", __func__, __LINE__, MIN_LEVL_PUBLISH_INTERVAL_MS);
                free(levl);
                free(ptr);
                return bus_error_invalid_input;
            }
            levl->levl_publish_interval = interval;
       }

        mac_data = strtok_r(NULL, ";", &saveptr);
        if (mac_data != NULL) {
            duration = atoi(mac_data);
            if (duration < MIN_LEVL_SOUNDING_DURATION_MS) {
                wifi_util_error_print(WIFI_APPS, "%s:%d The sounding duration should be at least %dms\n", __func__, __LINE__, MIN_LEVL_SOUNDING_DURATION_MS);
                free(levl);
                free(ptr);
                return bus_error_invalid_input;
            }
            levl->levl_sounding_duration = duration;
        }

        free(ptr);
    }

    push_levl_data_dml_to_ctrl_queue(&levl);
    if (levl != NULL) {
        free(levl);
    }
    return bus_error_success;
}
