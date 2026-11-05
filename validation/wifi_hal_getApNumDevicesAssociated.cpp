/*
 * HANDLER: wifi_hal_getApNumDevicesAssociated
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc_wifi_wrappers.c:628-648
 * (~/Desktop/G/rdk-wifi-hal), with get_interface_by_vap_index (src/wifi_hal_nl80211_utils.c:2312-2333)
 * copied verbatim next to it.  With RDK_GND_FIX 0 it is the VERBATIM original (reproduces the findings); with
 * RDK_GND_FIX 1 it carries FIX 1..2 below.
 *
 * Scaffolding only: the interface holds the REAL wifi_vap_info_t and the same u.ap / u.sta union as
 * wifi_hal_priv.h (u.ap.hapd first, num_sta inside it); g_wifi_hal holds num_radios, radio_info and the real
 * hapd_lock mutex; radios / hash_map_* walk a runner-owned array.  The prints are the real macros over the log
 * sink.  The function under test is renamed hwr_wifi_hal_getApNumDevicesAssociated (ipc_server_output already
 * stubs the real name).  (The copied lookup helper is declared static here only so the harnesses link together;
 * its body is verbatim.)
 */
#include "hwr_gnd.h"
#include <string.h>
#include <pthread.h>

/* 1 = with FIX 1..2, 0 = original unfixed function (set to 0 to reproduce the findings) */
#define RDK_GND_FIX  1

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define wifi_interface_info_t hwr_gnd_iface_t
#define wifi_radio_info_t     hwr_gnd_radio_t
#define g_wifi_hal            hwr_gnd_world
#define wifi_hal_getApNumDevicesAssociated hwr_wifi_hal_getApNumDevicesAssociated

hwr_gnd_world_t hwr_gnd_world = { 0, NULL, PTHREAD_MUTEX_INITIALIZER };

static hwr_gnd_iface_t *hash_map_get_first(hwr_gnd_map_t *map) { return (map && map->n > 0) ? map->items[0] : NULL; }
static hwr_gnd_iface_t *hash_map_get_next(hwr_gnd_map_t *map, hwr_gnd_iface_t *cur)
{
    for (int k = 0; map && k < map->n; k++) if (map->items[k] == cur) return (k + 1 < map->n) ? map->items[k + 1] : NULL;
    return NULL;
}

/* --- copied from wifi_hal_nl80211_utils.c:2312 --- */
static wifi_interface_info_t *get_interface_by_vap_index(unsigned int vap_index)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
    unsigned int i;

    // wifi_hal_dbg_print("%s:%d:{ vap_index:[%d] } g_wifi_hal.num_radios:[%d]\r\n",__func__, __LINE__, vap_index, g_wifi_hal.num_radios);
    for (i = 0; i < g_wifi_hal.num_radios; i++) {

        radio = &g_wifi_hal.radio_info[i];
        interface = hash_map_get_first(radio->interface_map);

        while (interface != NULL) {
            if (interface->vap_info.vap_index == vap_index) {
                return interface;
            }
            interface = hash_map_get_next(radio->interface_map, interface);
        }
    }

    return NULL;
}

/* --- copied from hal_ipc_wifi_wrappers.c:628 --- */
extern "C" {
INT wifi_hal_getApNumDevicesAssociated(INT apIndex, ULONG *output_ulong)
{
    wifi_interface_info_t *interface = NULL;

    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);

#if RDK_GND_FIX
    /* FIX 1: output_ulong is written (under hapd_lock) without a NULL check. */
    if (output_ulong == NULL) {
        wifi_hal_error_print("%s:%d: NULL output pointer for vap index %d\n", __func__, __LINE__, apIndex);
        return -1;
    }
#endif
    interface = get_interface_by_vap_index(apIndex);
    if (!interface)
    {
        wifi_hal_error_print("%s:%d: ERROR Interface for vap index %d doesn't exist.\n", __func__, __LINE__, apIndex);
        return -1;
    }

#if RDK_GND_FIX
    /* FIX 2: interface->u.ap is the AP member of a union that holds the STA state of a STA VAP, which has no
     * hostapd instance: num_sta was read from unrelated bytes and returned as a station count. */
    if (interface->vap_info.vap_mode != wifi_vap_mode_ap) {
        wifi_hal_error_print("%s:%d: vap index %d is not an AP vap\n", __func__, __LINE__, apIndex);
        return -1;
    }
#endif
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    *output_ulong = interface->u.ap.hapd.num_sta;
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

    wifi_hal_dbg_print("%s:%d: AP index %d, num assoc devs: %lu.\n", __func__, __LINE__, apIndex, *output_ulong);

    return 0;
}
}
