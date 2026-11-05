/*
 * HANDLER: wifi_hal_steering_clientRemove
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc_wifi_wrappers.c:387-413
 * (~/Desktop/G/rdk-wifi-hal).  With RDK_GRM_FIX 0 it is the VERBATIM original (reproduces the finding); with
 * RDK_GRM_FIX 1 it carries FIX 1 below.
 *
 * Scaffolding only: g_wifi_hal holds just steering_data_lock (real pthread mutex); get_interface_by_vap_index,
 * hash_map_get, wifi_steering_del_mac_list, steering_del_stalist (faithful model of src/wifi_hal_nl80211.c:1093:
 * clears the type bit, removes and "frees" the entry when no type is left - the freed entry is poisoned) and
 * nl80211_kick_device are stubs in the construct file (renamed hwr_grm_*); to_mac_str is the real helper
 * (wifi_hal_rdk_util.c:73); the prints are the real macros over the log sink.  The function under test is
 * renamed hwr_wifi_hal_steering_clientRemove.
 */
#include "hwr_grm.h"
#include <string.h>
#include <pthread.h>

/* 1 = with FIX 1, 0 = original unfixed function (set to 0 to reproduce the finding) */
#define RDK_GRM_FIX  1

#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define wifi_hal_info_print(format, ...)   hwr_print(0, format, ##__VA_ARGS__)
#define get_interface_by_vap_index   hwr_grm_get_interface
#define hash_map_get                 hwr_grm_hash_map_get
#define wifi_steering_del_mac_list   hwr_grm_del_mac_list
#define steering_del_stalist         hwr_grm_del_stalist
#define nl80211_kick_device          hwr_grm_kick_device
#define to_mac_str                   hwr_grm_to_mac_str
#define g_wifi_hal                   hwr_grm_world
#define wifi_hal_steering_clientRemove hwr_wifi_hal_steering_clientRemove

hwr_gcs_world_t hwr_grm_world = { PTHREAD_MUTEX_INITIALIZER };

/* wifi_hal_rdk_util.c:73, verbatim */
char *to_mac_str (const mac_address_t mac, mac_addr_str_t key) {
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return (char *)key;
}

//--------------------------------------------------------------------------------------------------
INT wifi_hal_steering_clientRemove( UINT steeringgroupIndex,
                                    INT apIndex,
                                    mac_address_t client_mac)
{
    wifi_interface_info_t *interface = NULL;
    bm_sta_list_t *bm_client_info = NULL;
    mac_addr_str_t sta_mac_str;
    char *key = NULL;

#if RDK_GRM_FIX
    /* FIX 1: client_mac was used without a check: to_mac_str() reads it right after the AP lookup and
     * nl80211_kick_device() copies 6 bytes from it, so a NULL client_mac crashed. */
    if (client_mac == NULL) {
        wifi_hal_error_print("%s:%d: NULL client mac for ap index %d\n", __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
#endif
    interface = get_interface_by_vap_index(apIndex);
    if(!interface) {
      wifi_hal_error_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, apIndex);
      return RETURN_ERR;
    }

    key = to_mac_str(client_mac, sta_mac_str);
    pthread_mutex_lock(&g_wifi_hal.steering_data_lock);
    bm_client_info = hash_map_get(interface->bm_sta_map, key);
    if (bm_client_info != NULL) {
        wifi_hal_info_print("%s:%d: remove client info:%s vap:%d\n", __func__, __LINE__, key, apIndex);
        /* remove from the deny list */
        wifi_steering_del_mac_list(apIndex, bm_client_info);
        steering_del_stalist(interface, bm_client_info->mac_addr, BM_STA_TYPE_CLIENT_SET);
    }
    pthread_mutex_unlock(&g_wifi_hal.steering_data_lock);
    return nl80211_kick_device(interface, client_mac);
}
