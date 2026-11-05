/*
 * HANDLER: wifi_hal_steering_clientSet
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc_wifi_wrappers.c:346-384
 * (~/Desktop/G/rdk-wifi-hal).  With RDK_GCS_FIX 0 it is the VERBATIM original (reproduces the finding); with
 * RDK_GCS_FIX 1 it carries FIX 1 below.
 *
 * Scaffolding only: g_wifi_hal holds just steering_data_lock (real pthread mutex); get_interface_by_vap_index,
 * steering_add_stalist and wifi_steering_del_mac_list are stubs in the construct file (renamed hwr_gcs_*,
 * other harness files define the real names); to_mac_str is the real helper (wifi_hal_rdk_util.c:73); the
 * prints are the real macros over the log sink; bm_sta_list_t is the real layout.  The function under test is
 * renamed hwr_wifi_hal_steering_clientSet.
 */
#include "hwr_gcs.h"
#include <string.h>
#include <pthread.h>

/* 1 = with FIX 1, 0 = original unfixed function (set to 0 to reproduce the finding) */
#define RDK_GCS_FIX  0

#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define wifi_hal_info_print(format, ...)   hwr_print(0, format, ##__VA_ARGS__)
#define get_interface_by_vap_index   hwr_gcs_get_interface
#define steering_add_stalist         hwr_gcs_add_stalist
#define wifi_steering_del_mac_list   hwr_gcs_del_mac_list
#define to_mac_str                   hwr_gcs_to_mac_str
#define g_wifi_hal                   hwr_gcs_world
#define wifi_hal_steering_clientSet  hwr_wifi_hal_steering_clientSet

hwr_gcs_world_t hwr_gcs_world = { PTHREAD_MUTEX_INITIALIZER };

/* wifi_hal_rdk_util.c:73, verbatim */
char *to_mac_str (const mac_address_t mac, mac_addr_str_t key) {
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return (char *)key;
}

//--------------------------------------------------------------------------------------------------
INT wifi_hal_steering_clientSet(UINT steeringgroupIndex,
                                INT apIndex, mac_address_t client_mac,
                                wifi_steering_clientConfig_t *config)
{
    wifi_interface_info_t *interface = NULL;
    mac_addr_str_t sta_mac_str;
    char *key = NULL;
    bm_sta_list_t *bm_client_info = NULL;

#if RDK_GCS_FIX
    /* FIX 1: client_mac and config were used without a check.  A NULL config reached the memcpy() below (and
     * was already dereferenced for the log), a NULL client_mac reached steering_add_stalist() / to_mac_str();
     * both crash, and a NULL config used to be noticed only after the station entry had been created.
     * Reject them before anything is looked up or created. */
    if (client_mac == NULL || config == NULL) {
        wifi_hal_error_print("%s:%d: NULL %s for ap index %d\n", __func__, __LINE__, client_mac == NULL ? "client mac" : "config", apIndex);
        return RETURN_ERR;
    }
#endif
    interface = get_interface_by_vap_index(apIndex);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: WiFi interface not found:%d\n", __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
    pthread_mutex_lock(&g_wifi_hal.steering_data_lock);
    bm_client_info = steering_add_stalist(interface, NULL, client_mac, BM_STA_TYPE_CLIENT_SET);
    if (bm_client_info == NULL) {
        wifi_hal_error_print("%s:%d: bm sta_list create failure for ap index %d\n", __func__, __LINE__, apIndex);
        pthread_mutex_unlock(&g_wifi_hal.steering_data_lock);
        return RETURN_ERR;
    } else {
        key = to_mac_str(client_mac, sta_mac_str);
        memcpy(&bm_client_info->bm_client_cfg, config, sizeof(wifi_steering_clientConfig_t));
        if (!config->rssiProbeLWM && !config->rssiProbeHWM) {
            if (wifi_steering_del_mac_list(apIndex, bm_client_info) == RETURN_OK) {
                wifi_hal_info_print("Remove MAC=%s from maclist for vap:%d\n", key, apIndex);
            }
        }
        wifi_hal_info_print("%s:%d: Wi-Fi steering group:%d for vap:%d and client:%s\n", __func__, __LINE__,
                                steeringgroupIndex, apIndex, key);
        wifi_hal_info_print("rssiProbe HWM:%d-LWM:%d rssiAuthHWM:%d-LWM:%d rssiInactXing:%d"
                                "rssiHighXing:%d-Low:%d authRejectReason:%d\n",
                                config->rssiProbeHWM, config->rssiProbeLWM, config->rssiAuthHWM, config->rssiAuthLWM,
                                config->rssiInactXing, config->rssiHighXing, config->rssiLowXing, config->authRejectReason);
    }
    pthread_mutex_unlock(&g_wifi_hal.steering_data_lock);

    return RETURN_OK;
}
