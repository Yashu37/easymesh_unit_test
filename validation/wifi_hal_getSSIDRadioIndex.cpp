/*
 * HANDLER: wifi_hal_getSSIDRadioIndex
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc_wifi_wrappers.c:135-149
 * (~/Desktop/G/rdk-wifi-hal), with get_interface_by_vap_index (src/wifi_hal_nl80211_utils.c) copied verbatim
 * next to it.  With RDK_GSR_FIX 0 it is the VERBATIM original (reproduces the findings); with RDK_GSR_FIX 1
 * it carries FIX 1 below.
 *
 * Scaffolding only: the interface holds the REAL wifi_vap_info_t (wifi_hal.h); radios / g_wifi_hal /
 * hash_map_* are minimal (hwr_gsr.h) and walk a runner-owned array.  The function under test is renamed
 * hwr_wifi_hal_getSSIDRadioIndex (ipc_server_output already stubs the real name).

 * (The copied lookup helper is declared static here only so the harnesses link together; its body is verbatim.)
 */
#include "hwr_gsr.h"

/* 1 = with FIX 1, 0 = original unfixed function (set to 0 to reproduce the findings) */
#define RDK_GSR_FIX  0

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define wifi_interface_info_t hwr_gsr_iface_t
#define wifi_radio_info_t     hwr_gsr_radio_t
#define g_wifi_hal            hwr_gsr_world
#define wifi_hal_getSSIDRadioIndex hwr_wifi_hal_getSSIDRadioIndex

hwr_gsr_world_t hwr_gsr_world;

static hwr_gsr_iface_t *hash_map_get_first(hwr_gsr_map_t *map) { return (map && map->n > 0) ? map->items[0] : NULL; }
static hwr_gsr_iface_t *hash_map_get_next(hwr_gsr_map_t *map, hwr_gsr_iface_t *cur)
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

/* --- copied from hal_ipc_wifi_wrappers.c:135 --- */
extern "C" {
INT wifi_hal_getSSIDRadioIndex( INT ssidIndex,
                                INT *radioIndex)
{
    wifi_interface_info_t *interface = NULL;
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);

#if RDK_GSR_FIX
    /* FIX 1: radioIndex is written unchecked. */
    if (radioIndex == NULL) {
        return RETURN_ERR;
    }
#endif
    interface = get_interface_by_vap_index(ssidIndex);
    if(!interface) {
      wifi_hal_error_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, ssidIndex);
      return RETURN_ERR;
    }
    *radioIndex = interface->vap_info.radio_index;

    return 0;
}
}
