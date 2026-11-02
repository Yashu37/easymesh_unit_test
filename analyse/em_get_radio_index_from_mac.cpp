/*
 * HANDLER: em_get_radio_index_from_mac
 *
 * Copied VERBATIM from OneWifi source/apps/em/wifi_em.c (only "static"
 * dropped). Local arrays:
 *   - mac_addr_str_t rad_str / bss_str (char[18]) : filled by to_mac_str() --
 *     a bounded snprintf into 18 bytes; used only for debug/error prints.
 *   - mac_addr_t radio_mac (unsigned char[6])     : filled by
 *     mac_address_from_name() and compared with memcmp(.., sizeof(mac_addr_t)).
 * All three are fixed-size internal stack arrays (ASan stack redzones guard
 * them); the loops are bounded by num_vaps and the radio_interface_map size.
 * No index can run past an array, so this is a SAFE lookup.
 *
 * Scaffolding (NOT under test): getNumberRadios / get_wifidb_vap_map /
 * get_wifimgr_obj / to_mac_str / mac_address_from_name are stubbed and driven
 * by the erm_* globals. NO ASan calls here.
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

/* wifi_vap_info_map_t + erm_* vap types come from common.h */

/* --- scaffolding stubs driven by erm_* globals (defined in constructor) --- */
static unsigned int getNumberRadios(void) { return (unsigned int)erm_num_radios; }
static wifi_mgr_t  *get_wifimgr_obj(void) { return (wifi_mgr_t *)erm_mgr_buf; }
static void        *get_wifidb_vap_map(int i) { return erm_vap_present[i] ? (void *)&erm_vap_maps[i] : NULL; }
static char        *to_mac_str(mac_address_t mac, mac_addr_str_t key)
{
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}
/* looks up a mac for an interface name in the erm_iface_* table; RETURN_ERR if absent */
static int mac_address_from_name(const char *name, mac_addr_t mac)
{
    for (int i = 0; i < erm_iface_count; i++) {
        if (strcmp(name, erm_iface_name[i]) == 0) { memcpy(mac, erm_iface_mac[i], 6); return RETURN_OK; }
    }
    return RETURN_ERR;
}

/* ================= VERBATIM from wifi_em.c (static dropped) ================= */
int em_get_radio_index_from_mac(mac_addr_t ruuid)
{
    unsigned int num_of_radios = getNumberRadios();
    wifi_vap_info_map_t *vap_map;
    mac_addr_str_t rad_str;
    mac_addr_str_t bss_str;
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();
    wifi_platform_property_t *wifi_prop = &wifi_mgr->hal_cap.wifi_prop;

    to_mac_str(ruuid, rad_str);

    for (int i = 0; i < num_of_radios; i++) {
        vap_map = (wifi_vap_info_map_t *)get_wifidb_vap_map(i);

        for (int j = 0; vap_map && j < vap_map->num_vaps; j++) {
            to_mac_str(vap_map->vap_array[j].u.bss_info.bssid, bss_str);
            if (memcmp(ruuid, vap_map->vap_array[j].u.bss_info.bssid, sizeof(mac_addr_t)) == 0) {
                return vap_map->vap_array[j].radio_index;
            }
        }

        /* Check against radio's own interface MAC */
        for (unsigned int k = 0;
             k < (sizeof(wifi_prop->radio_interface_map) / sizeof(radio_interface_mapping_t)); k++) {
            if (wifi_prop->radio_interface_map[k].radio_index == i) {
                mac_addr_t radio_mac = { 0 };
                if (mac_address_from_name(wifi_prop->radio_interface_map[k].interface_name, radio_mac) != RETURN_OK) {
                    wifi_util_dbg_print(WIFI_EM, "%s:%d failed to get MAC for iface %s\n",
                        __func__, __LINE__, wifi_prop->radio_interface_map[k].interface_name);
                    break;
                }
                if (memcmp(ruuid, radio_mac, sizeof(mac_addr_t)) == 0)
                    return i;
                break;
            }
        }
    }

    wifi_util_error_print(WIFI_EM, "%s:%d Radio Index not found for radio mac: %s\n", __func__, __LINE__, rad_str);

    return RETURN_ERR;
}
