/*
 * HANDLER: em_get_vap_index_from_bssid
 *
 * Copied VERBATIM from OneWifi source/apps/em/wifi_em.c (only "static"
 * dropped). Local arrays:
 *   - mac_addr_str_t bss_str, search_str (char[18]) : filled by to_mac_str()
 *     (bounded snprintf into 18 bytes), used only for debug/error prints.
 * Both are fixed-size internal stack arrays (ASan stack redzones guard them);
 * the loops are bounded by num_vaps. STA-mesh vaps are skipped. The match is a
 * memcmp over sizeof(mac_addr_t). No index can run past an array -> SAFE.
 *
 * Scaffolding (NOT under test): getNumberRadios / get_wifidb_vap_map /
 * to_mac_str / isVapSTAMesh are stubbed and driven by the evb_* globals.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

#ifndef RETURN_OK
#define RETURN_OK  0
#endif
#ifndef RETURN_ERR
#define RETURN_ERR (-1)
#endif
#define WIFI_EM 0
#ifndef wifi_util_dbg_print
#define wifi_util_dbg_print(m, ...)   do {} while (0)
#define wifi_util_error_print(m, ...) do {} while (0)
#endif

/* --- scaffolding stubs driven by evb_* globals (defined in constructor) --- */
static unsigned int getNumberRadios(void) { return (unsigned int)evb_num_radios; }
static void        *get_wifidb_vap_map(int i) { return evb_vap_present[i] ? (void *)&evb_vap_maps[i] : NULL; }
static char        *to_mac_str(mac_address_t mac, mac_addr_str_t key)
{
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}
static int isVapSTAMesh(unsigned int vap_index) { return (vap_index < 64) ? evb_mesh_vap[vap_index] : 0; }

/* ================= VERBATIM from wifi_em.c (static dropped) ================= */
int em_get_vap_index_from_bssid(mac_addr_t bssid)
{
    unsigned int num_of_radios = getNumberRadios();
    wifi_vap_info_map_t *vap_map;
    mac_addr_str_t bss_str, search_str;

    to_mac_str(bssid, search_str);

    for (int i = 0; i < num_of_radios; i++) {
        vap_map = (wifi_vap_info_map_t *)get_wifidb_vap_map(i);
        if (vap_map == NULL) {
            continue;
        }
        for (int j = 0; j < vap_map->num_vaps; j++) {
            if (isVapSTAMesh(vap_map->vap_array[j].vap_index)) {
                continue;
            }
            to_mac_str(vap_map->vap_array[j].u.bss_info.bssid, bss_str);
            if (memcmp(bssid, vap_map->vap_array[j].u.bss_info.bssid, sizeof(mac_addr_t)) == 0) {
                wifi_util_dbg_print(WIFI_EM, "%s:%d VAP Index: %d found for BSSID: %s\n", __func__,
                    __LINE__, vap_map->vap_array[j].vap_index, bss_str);
                return vap_map->vap_array[j].vap_index;
            }
        }
    }

    wifi_util_error_print(WIFI_EM, "%s:%d VAP Index not found for BSSID %s\n", __func__, __LINE__,
        search_str);

    return RETURN_ERR;
}
