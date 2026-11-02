/*
 * HANDLER: webconfig_hal_csi_data_apply
 *
 * Function copied VERBATIM from OneWifi source/apps/csi/wifi_csi_analytics.c
 * (only "static" dropped so the runner can call it). The two static helpers
 * mac_exists_in_list and add_str_mac_addr are copied VERBATIM too (they do the
 * actual total_str_mac writes). No fixes. Local arrays: mac_str[18]
 * (to_mac_str) and total_str_mac[MAX_MACLIST_SIZE=512] (built by
 * add_str_mac_addr: strcat/snprintf, guarded by str_len + MAX_MAC_STR_SIZE).
 *
 * Redirect: to_mac_str()->whc slot(18); the RUNNER poisons that slot past 18
 * and the caller apps / decoded-data past their sizes, and each csi_data
 * entry. total_str_mac[512] is ASan-stack guarded (strcat/snprintf are ASan
 * intercepted), so an append overrun would be caught.
 *
 * Scaffolding (NOT the function under test): queue_count/queue_peek,
 * update_mac_list are file-local stubs; csi_data_t / the decoded-data struct
 * are local subsets.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include "common.h"

#define WIFI_APPS 0
#define RETURN_OK 0
#define RETURN_ERR -1
#define CSI_CLIENT_PER_SESSION 64
typedef struct { unsigned long csi_session_num; bool enabled; unsigned int csi_client_count; unsigned char csi_client_list[CSI_CLIENT_PER_SESSION][6]; } csi_data_t;

static void whc_print(int m,const char*f,...){char sc[512];va_list ap;(void)m;va_start(ap,f);vsnprintf(sc,sizeof(sc),f,ap);va_end(ap);}
#define wifi_util_dbg_print   whc_print
#define wifi_util_error_print whc_print
static unsigned int queue_count(void*q){(void)q;return whc_count;}
static void *queue_peek(void*q,unsigned int i){(void)q;return (i<whc_count)?whc_items[i]:NULL;}
static void update_mac_list(wifi_app_t*a,char*total){(void)a;snprintf(whc_result,sizeof(whc_result),"%s",total);whc_update_calls++;}
static char *whc_to_mac_str(unsigned char*mac,char*key){memset(whc_slot_mac,0,WHC_MAC_SZ);snprintf(whc_slot_mac,18,"%02x:%02x:%02x:%02x:%02x:%02x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);memcpy(key,whc_slot_mac,WHC_MAC_SZ);return key;}
#define to_mac_str(m,k)  whc_to_mac_str((m),(k))

/* verbatim helpers from source/apps/csi/wifi_csi_analytics.c */
static char *mac_exists_in_list(const char *total_mac, const char *mac_to_check)
{
    return (strstr(total_mac, mac_to_check));
}

static int add_str_mac_addr(char *total_mac, const char *str_mac)
{
    if (mac_exists_in_list((const char *)total_mac, str_mac) == NULL) {
        uint32_t str_len = strlen(total_mac);
        if (str_len + MAX_MAC_STR_SIZE > MAX_MACLIST_SIZE) {
            wifi_util_error_print(WIFI_APPS, "%s:%d: max stored mac addr reached:%s\n", __func__,
                __LINE__, total_mac);
            return RETURN_ERR;
        } else if (str_len != 0) {
            strcat(total_mac, ",");
            strcat(total_mac, str_mac);
        } else {
            snprintf(total_mac, MAX_MACLIST_SIZE, "%s", str_mac);
        }
    }
    return RETURN_OK;
}


/* --- copied verbatim from source/apps/csi/wifi_csi_analytics.c (only "static" dropped) --- */
int webconfig_hal_csi_data_apply(wifi_app_t *apps, webconfig_subdoc_decoded_data_t *data)
{
    queue_t *new_config;
    new_config = data->csi_data_queue;
    uint32_t index = 0, s_index = 0, total_session;
    csi_data_t *new_csi_data;
    csi_analytics_info_t *csi_info = &apps->data.u.csi_analytics;
    mac_addr_str_t mac_str;
    char total_str_mac[MAX_MACLIST_SIZE] = { 0 };

    // check new configuration of csi clients
    wifi_util_dbg_print(WIFI_APPS, "%s webconfig csi config:%p\r\n", __func__, new_config);
    if (new_config == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s webconfig csi config is NULL\r\n", __func__);
        return RETURN_ERR;
    }

    total_session = queue_count(new_config);
    for (index = 0; index < total_session; index++) {
        new_csi_data = (csi_data_t *)queue_peek(new_config, index);
        if (new_csi_data != NULL) {
            if (new_csi_data->csi_session_num == csi_info->csi_session_index) {
                wifi_util_dbg_print(WIFI_APPS,
                    "%s:%d csi own session index:%d"
                    " index:%d\n",
                    __func__, __LINE__, csi_info->csi_session_index, index);
            } else if (new_csi_data->enabled == false) {
                wifi_util_dbg_print(WIFI_APPS,
                    "%s:%d csi not enabled for"
                    " session index:%d\n",
                    __func__, __LINE__, new_csi_data->csi_session_num);
            } else {
                for (s_index = 0; s_index < new_csi_data->csi_client_count; s_index++) {
                    memset(mac_str, 0, MAX_MAC_STR_SIZE);
                    to_mac_str(new_csi_data->csi_client_list[s_index], mac_str);
                    if (add_str_mac_addr(total_str_mac, mac_str) != RETURN_OK) {
                        break;
                    }
                }
            }
        }
    }

    update_mac_list(apps, total_str_mac);

    return RETURN_OK;
}
