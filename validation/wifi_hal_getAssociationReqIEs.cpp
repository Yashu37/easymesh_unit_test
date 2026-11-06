/*
 * HANDLER: wifi_hal_getAssociationReqIEs
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc_wifi_wrappers.c:463-492 (~/Desktop/G/rdk-wifi-hal).  This
 * file holds ONLY THE FIXED code: it carries FIX 1..3 below.
 *
 * Scaffolding only: g_wifi_hal holds just hapd_lock (real pthread mutex); the interface has the REAL
 * wifi_vap_info_t and the same u.ap / u.sta union as wifi_hal_priv.h (ap.hapd first); get_interface_by_vap_index
 * and ap_get_sta are stubs in the construct file (renamed hwr_gai_*); ap_get_sta models libhostap's (hashes the
 * 6 MAC bytes, reads the hostapd instance's station table, returns NULL for an unknown client); struct sta_info
 * keeps only assoc_req / assoc_req_len.  The prints are the real macros over the log sink.  The function under
 * test is renamed hwr_wifi_hal_getAssociationReqIEs.
 */
#include "hwr_gai.h"
#include <string.h>
#include <pthread.h>


#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define sta_info                     hwr_gai_sta_info
#define get_interface_by_vap_index   hwr_gai_get_interface
#define ap_get_sta                   hwr_gai_ap_get_sta
#define g_wifi_hal                   hwr_gai_world
#define wifi_hal_getAssociationReqIEs hwr_wifi_hal_getAssociationReqIEs

hwr_gai_world_t hwr_gai_world = { PTHREAD_MUTEX_INITIALIZER };

//--------------------------------------------------------------------------------------------------
extern "C" {
INT wifi_hal_getAssociationReqIEs(  UINT apIndex,
                                    const mac_address_t *clientMacAddress,
                                    CHAR *req_ies,
                                    UINT req_ies_size,
                                    UINT *req_ies_len)
{

    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);

    wifi_interface_info_t *interface = NULL;
    struct sta_info *station = NULL;

    /* FIX 1: clientMacAddress, req_ies and req_ies_len are used without a check (ap_get_sta() hashes the MAC,
     * memcpy() writes req_ies, *req_ies_len is written). */
    if (clientMacAddress == NULL || req_ies == NULL || req_ies_len == NULL) {
        wifi_hal_error_print("%s:%d: NULL argument for ap index:%u\n", __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
    interface = get_interface_by_vap_index(apIndex);
    if(!interface) {
      wifi_hal_error_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, apIndex);
      return RETURN_ERR;
    }
    /* FIX 2: &interface->u.ap.hapd is the AP member of a union that holds the STA state of a STA VAP, which has
     * no hostapd instance: ap_get_sta() used garbage as a hostapd_data. */
    if (interface->vap_info.vap_mode != wifi_vap_mode_ap) {
        wifi_hal_error_print("%s:%d: vap:%u is not an AP vap\n", __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    station = ap_get_sta(&interface->u.ap.hapd, (const u8 *) clientMacAddress);
    /* FIX 3: ap_get_sta() returns NULL for a client that is not associated; station->assoc_req_len was read
     * unchecked (NULL dereference, with hapd_lock held). */
    if (station == NULL) {
        wifi_hal_error_print("%s:%d: client not found on ap index:%u\n", __func__, __LINE__, apIndex);
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
        return RETURN_ERR;
    }
    if (req_ies_size < station->assoc_req_len) {
      wifi_hal_error_print("%s:%d: req_ies_size %u is too small (should be at least %zu)\n", __func__, __LINE__, req_ies_size, station->assoc_req_len);
      pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
      return RETURN_ERR;
    }

    memcpy(req_ies, station->assoc_req, station->assoc_req_len);
    *req_ies_len = station->assoc_req_len;
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    return 0;
}
}
