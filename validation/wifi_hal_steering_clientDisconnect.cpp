/*
 * HANDLER: wifi_hal_steering_clientDisconnect
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc_wifi_wrappers.c:416-442
 * (~/Desktop/G/rdk-wifi-hal).  With RDK_GSD_FIX 0 it is the VERBATIM original (reproduces the finding); with
 * RDK_GSD_FIX 1 it carries FIX 1 below.
 *
 * Scaffolding only: g_wifi_hal holds just hapd_lock (real pthread mutex); the interface has the REAL
 * wifi_vap_info_t and the same u.ap / u.sta union as wifi_hal_priv.h (ap.hapd first); get_interface_by_vap_index
 * and ap_sta_disconnect are stubs in the construct file (renamed hwr_gsd_*); ap_sta_disconnect models
 * libhostap's (src/ap/sta_info.c:1919): with an address it dereferences hapd->conf, with a NULL address it
 * returns without doing anything.  The prints are the real macros over the log sink.  The function under test
 * is renamed hwr_wifi_hal_steering_clientDisconnect.
 */
#include "hwr_gsd.h"
#include <string.h>
#include <pthread.h>

/* 1 = with FIX 1, 0 = original unfixed function (set to 0 to reproduce the finding) */
#define RDK_GSD_FIX  1

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_info_print(format, ...)   hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define get_interface_by_vap_index   hwr_gsd_get_interface
#define ap_sta_disconnect            hwr_gsd_ap_sta_disconnect
#define g_wifi_hal                   hwr_gsd_world
#define wifi_hal_steering_clientDisconnect hwr_wifi_hal_steering_clientDisconnect

hwr_gsd_world_t hwr_gsd_world = { PTHREAD_MUTEX_INITIALIZER };

//--------------------------------------------------------------------------------------------------
extern "C" {
INT wifi_hal_steering_clientDisconnect( UINT steeringgroupIndex,
                                        INT apIndex,
                                        mac_address_t client_mac,
                                        wifi_disconnectType_t type,
                                        UINT reason)
{
    wifi_interface_info_t *interface;
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);
    wifi_hal_info_print("%s:%d: apIndex:%d steeringgroupIndex:%d type:%d reason:%d\n", __func__, __LINE__, apIndex, steeringgroupIndex, type, reason);

    interface = get_interface_by_vap_index(apIndex);
    if(!interface) {
      wifi_hal_error_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, apIndex);
      return RETURN_ERR;
    }

#if RDK_GSD_FIX
    /* FIX 1: (a) a NULL client_mac made ap_sta_disconnect() return without doing anything and RETURN_OK was
     * reported; (b) a STA VAP has no hostapd instance: interface->u.ap.hapd is the AP member of a union that
     * holds the STA state there, and ap_sta_disconnect() used it as a hostapd_data (crash / corruption).
     * Both are rejected here. */
    if (client_mac == NULL) {
        wifi_hal_error_print("%s:%d: NULL client mac for ap index:%d\n", __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
    if (interface->vap_info.vap_mode != wifi_vap_mode_ap) {
        wifi_hal_error_print("%s:%d: vap:%d is not an AP vap\n", __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
#endif
    if ((type == DISCONNECT_TYPE_DEAUTH) || (type == DISCONNECT_TYPE_DISASSOC)) {
        pthread_mutex_lock(&g_wifi_hal.hapd_lock);
        ap_sta_disconnect(&interface->u.ap.hapd, NULL, client_mac, reason);
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    } else {
        wifi_hal_info_print("%s:%d: apIndex:%d unknown event type:%d\n", __func__, __LINE__, apIndex, type);
        return RETURN_ERR;
    }

    return RETURN_OK;
}
}
