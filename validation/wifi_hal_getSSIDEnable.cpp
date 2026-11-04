/*
 * HANDLER: wifi_hal_getSSIDEnable
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc_wifi_wrappers.c:118-132
 * (~/Desktop/G/rdk-wifi-hal), with get_interface_by_vap_index (src/wifi_hal_nl80211_utils.c:2312-2333)
 * copied verbatim next to it.  With RDK_GSE_FIX 0 it is the VERBATIM original (reproduces the findings);
 * with RDK_GSE_FIX 1 it carries FIX 1..2 below.
 *
 * Scaffolding only: the interface holds the REAL wifi_vap_info_t (real packed union of bss_info / sta_info,
 * from wifi_hal.h); radios / g_wifi_hal / hash_map_* are minimal (hwr_gse.h) and walk a runner-owned array.
 * The function under test is renamed hwr_wifi_hal_getSSIDEnable (ipc_server_output already stubs the real name).
 */
#include "hwr_gse.h"

/* 1 = with FIX 1..2, 0 = original unfixed function (set to 0 to reproduce the findings) */
#define RDK_GSE_FIX  1

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define wifi_interface_info_t hwr_gse_iface_t
#define wifi_radio_info_t     hwr_gse_radio_t
#define g_wifi_hal            hwr_gse_world
#define wifi_hal_getSSIDEnable hwr_wifi_hal_getSSIDEnable

hwr_gse_world_t hwr_gse_world;

static hwr_gse_iface_t *hash_map_get_first(hwr_gse_map_t *map) { return (map && map->n > 0) ? map->items[0] : NULL; }
static hwr_gse_iface_t *hash_map_get_next(hwr_gse_map_t *map, hwr_gse_iface_t *cur)
{
    for (int k = 0; map && k < map->n; k++) if (map->items[k] == cur) return (k + 1 < map->n) ? map->items[k + 1] : NULL;
    return NULL;
}

/* --- copied from wifi_hal_nl80211_utils.c:2312 --- */
wifi_interface_info_t *get_interface_by_vap_index(unsigned int vap_index)
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

/* --- copied from hal_ipc_wifi_wrappers.c:118 --- */
extern "C" {
INT wifi_hal_getSSIDEnable( INT ssidIndex,
                            BOOL *output_bool)
{
    wifi_interface_info_t *interface = NULL;
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);

#if RDK_GSE_FIX
    /* FIX 1: output_bool is written unchecked. */
    if (output_bool == NULL) {
        return RETURN_ERR;
    }
#endif
    interface = get_interface_by_vap_index(ssidIndex);
    if(!interface){
      wifi_hal_error_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, ssidIndex);
      return RETURN_ERR;
    }
#if RDK_GSE_FIX
    /* FIX 2: vap_info.u is a union; bss_info is only valid for an AP VAP.  For a STA VAP the same bytes are
     * part of sta_info (bss_info.enabled is at offset 33, sta_info.enabled at offset 70), so the value
     * returned was whatever sta_info holds there.  Read the member that matches the VAP mode. */
    if (interface->vap_info.vap_mode == wifi_vap_mode_ap) {
        *output_bool = interface->vap_info.u.bss_info.enabled;
    } else if (interface->vap_info.vap_mode == wifi_vap_mode_sta) {
        *output_bool = interface->vap_info.u.sta_info.enabled;
    } else {
        return RETURN_ERR;
    }
#else
    *output_bool = interface->vap_info.u.bss_info.enabled;
#endif

    return 0;
}
}
