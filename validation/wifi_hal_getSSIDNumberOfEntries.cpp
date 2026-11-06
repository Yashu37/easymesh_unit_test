/*
 * HANDLER: wifi_hal_getSSIDNumberOfEntries
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc_wifi_wrappers.c:35-62 (~/Desktop/G/rdk-wifi-hal), with
 * get_radio_by_rdk_index (src/wifi_hal_nl80211_utils.c:2271-2283) copied verbatim next to it.  This file holds ONLY THE
 * FIXED code: it carries FIX 1..2 below.
 *
 * Scaffolding only: g_wifi_hal / radio / interface are minimal types holding just the fields the function
 * reads (hwr_ssid.h); hash_map_get_first / hash_map_get_next walk a small runner-owned array of interface
 * pointers.  The function under test is renamed hwr_wifi_hal_getSSIDNumberOfEntries because the
 * ipc_server_output harness already defines a stub named wifi_hal_getSSIDNumberOfEntries.

 * (The copied lookup helper is declared static here only so the harnesses link together; its body is verbatim.)
 */
#include "hwr_ssid.h"


#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_interface_info_t hwr_iface_t
#define wifi_radio_info_t     hwr_radio_t
#define g_wifi_hal            hwr_g_wifi_hal
#define wifi_hal_getSSIDNumberOfEntries hwr_wifi_hal_getSSIDNumberOfEntries

hwr_g_wifi_hal_t hwr_g_wifi_hal;

static hwr_iface_t *hash_map_get_first(hwr_hash_map_t *map) { return (map && map->n > 0) ? map->items[0] : NULL; }
static hwr_iface_t *hash_map_get_next(hwr_hash_map_t *map, hwr_iface_t *cur)
{
    for (int k = 0; map && k < map->n; k++) if (map->items[k] == cur) return (k + 1 < map->n) ? map->items[k + 1] : NULL;
    return NULL;
}

/* --- copied from wifi_hal_nl80211_utils.c:2271 --- */
static wifi_radio_info_t *get_radio_by_rdk_index(wifi_radio_index_t index)
{
    wifi_radio_info_t *radio;
    unsigned int i;

    for (i = 0; i < g_wifi_hal.num_radios; i++) {
        radio = &g_wifi_hal.radio_info[i];
        if (radio->rdk_radio_index == index) {
            return radio;
        }
    }
    return NULL;
}

/* --- copied from hal_ipc_wifi_wrappers.c:35 --- */
extern "C" {
INT wifi_hal_getSSIDNumberOfEntries(ULONG *numEntries)
{
    wifi_interface_info_t *interface = NULL;
    wifi_radio_info_t *radio = NULL;
    ULONG ssid_num = 0;

    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);
    /* FIX 1: numEntries is written unchecked. */
    if (numEntries == NULL) {
        return RETURN_ERR;
    }
    // iterate through num radios over all interfaces
    for (int i = 0; i < g_wifi_hal.num_radios; i ++)
    {
      /* FIX 2: i is a position in radio_info[], not an rdk radio index: looking the radio up by rdk index
       * skipped radios whose rdk_radio_index is not exactly their position (and counted none of their SSIDs). */
      radio = &g_wifi_hal.radio_info[i];
      if (radio) {
        interface = hash_map_get_first(radio->interface_map);
        while (interface != NULL)
        {
          if (((int)interface->vap_info.vap_index >= 0) && (interface->vap_info.vap_mode == wifi_vap_mode_ap)) {
            ssid_num++;
          }
          interface = hash_map_get_next(radio->interface_map, interface);
        }
      }
    }
    *numEntries = ssid_num;

    wifi_hal_dbg_print("%s:%d: Num of SSIDs: %lu.\n", __func__, __LINE__, *numEntries);

    return 0;
}
}
