/*
 * HANDLER: wifi_hal_getSSIDName
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc_wifi_wrappers.c:445-460
 * (~/Desktop/G/rdk-wifi-hal), with get_interface_by_vap_index (src/wifi_hal_nl80211_utils.c) copied verbatim
 * next to it (declared static here only so the harnesses link together).  With RDK_GSM_FIX 0 it is the
 * VERBATIM original (reproduces the findings); with RDK_GSM_FIX 1 it carries FIX 1..3 below.
 *
 * Scaffolding only: the interface holds the REAL wifi_vap_info_t (wifi_hal.h); radios / g_wifi_hal /
 * hash_map_* are minimal (hwr_gsm.h) and walk a runner-owned array.  The function under test is renamed
 * hwr_wifi_hal_getSSIDName (ipc_server_output already stubs the real name).
 */
#include "hwr_gsm.h"
#include <string.h>

/* 1 = with FIX 1..3, 0 = original unfixed function (set to 0 to reproduce the findings) */
#define RDK_GSM_FIX  0

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define wifi_interface_info_t hwr_gsm_iface_t
#define wifi_radio_info_t     hwr_gsm_radio_t
#define g_wifi_hal            hwr_gsm_world
#define wifi_hal_getSSIDName hwr_wifi_hal_getSSIDName

hwr_gsm_world_t hwr_gsm_world;

static hwr_gsm_iface_t *hash_map_get_first(hwr_gsm_map_t *map) { return (map && map->n > 0) ? map->items[0] : NULL; }
static hwr_gsm_iface_t *hash_map_get_next(hwr_gsm_map_t *map, hwr_gsm_iface_t *cur)
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

/* --- copied from hal_ipc_wifi_wrappers.c:445 --- */
extern "C" {
INT wifi_hal_getSSIDName(   INT apIndex,
                            CHAR *output_string)
{
    wifi_interface_info_t *interface = NULL;
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);

#if RDK_GSM_FIX
    /* FIX 1: output_string is written unchecked. */
    if (output_string == NULL) {
        return RETURN_ERR;
    }
#endif
    interface = get_interface_by_vap_index(apIndex);
    if(!interface) {
      wifi_hal_error_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, apIndex);
      return RETURN_ERR;
    }

#if RDK_GSM_FIX
    {
        /* FIX 2: strcpy() of a field that is not guaranteed to be NUL terminated (33 bytes for an AP, 32 for a
         * STA) ran past the end of the field and of the caller's buffer.  Copy at most the SSID bytes.
         * FIX 3: the SSID field has a different size in the two union members (bss_info 33 bytes, sta_info
         * 32 bytes), so the bound is taken from the member that matches the VAP mode; other modes are rejected
         * (hardening, neither member is valid for a monitor VAP). */
        const char *ssid;
        size_t max, n;

        if (interface->vap_info.vap_mode == wifi_vap_mode_ap) {
            ssid = interface->vap_info.u.bss_info.ssid;
            max = sizeof(interface->vap_info.u.bss_info.ssid) - 1;
        } else if (interface->vap_info.vap_mode == wifi_vap_mode_sta) {
            ssid = interface->vap_info.u.sta_info.ssid;
            max = sizeof(interface->vap_info.u.sta_info.ssid);
        } else {
            return RETURN_ERR;
        }
        for (n = 0; n < max && ssid[n] != '\0'; n++) {
        }
        memcpy(output_string, ssid, n);
        output_string[n] = '\0';
    }
#else
    strcpy(output_string, interface->vap_info.u.bss_info.ssid);
#endif

    return 0;
}
}
