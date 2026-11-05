/*
 * HANDLER: wifi_hal_setNeighborReportActivation
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc_wifi_wrappers.c:576-591
 * (~/Desktop/G/rdk-wifi-hal), with get_interface_by_vap_index (src/wifi_hal_nl80211_utils.c:2312-2333)
 * copied verbatim next to it.  With RDK_SNR_FIX 0 it is the VERBATIM original (reproduces the findings);
 * with RDK_SNR_FIX 1 it carries FIX 1 below.
 *
 * Scaffolding only: the interface holds the REAL wifi_vap_info_t (real packed union of bss_info / sta_info,
 * from wifi_hal.h); radios / g_wifi_hal / hash_map_* are minimal (hwr_snr.h) and walk a runner-owned array.
 * The function under test is renamed hwr_wifi_hal_setNeighborReportActivation (ipc_server_output already stubs the real name).
 * (The copied lookup helper is declared static here only so the harnesses link together; its body is verbatim.)
 */
#include "hwr_snr.h"

/* 1 = with FIX 1, 0 = original unfixed function (set to 0 to reproduce the findings) */
#define RDK_SNR_FIX  0

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define wifi_interface_info_t hwr_snr_iface_t
#define wifi_radio_info_t     hwr_snr_radio_t
#define g_wifi_hal            hwr_snr_world
#define wifi_hal_setNeighborReportActivation hwr_wifi_hal_setNeighborReportActivation

hwr_snr_world_t hwr_snr_world;

static hwr_snr_iface_t *hash_map_get_first(hwr_snr_map_t *map) { return (map && map->n > 0) ? map->items[0] : NULL; }
static hwr_snr_iface_t *hash_map_get_next(hwr_snr_map_t *map, hwr_snr_iface_t *cur)
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

/* --- copied from hal_ipc_wifi_wrappers.c:576 --- */
extern "C" {
INT wifi_hal_setNeighborReportActivation(UINT apIndex, BOOL activate)
{
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);

    wifi_interface_info_t *interface = NULL;
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);
    interface = get_interface_by_vap_index(apIndex);

    if(!interface) {
      wifi_hal_error_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, apIndex);
      return RETURN_ERR;
    }
#if RDK_SNR_FIX
    /* FIX 1: vap_info.u is a union and nbrReportActivated only exists in bss_info (AP VAPs).  For a STA VAP the
     * same byte (offset 45) is part of sta_info, so the write corrupted the STA configuration (and a monitor
     * VAP has neither member).  Reject non-AP VAPs. */
    if (interface->vap_info.vap_mode != wifi_vap_mode_ap) {
        wifi_hal_error_print("%s:%d: vap:%u is not an AP vap\n", __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
#endif
    interface->vap_info.u.bss_info.nbrReportActivated = activate;

    return 0;
}
}
