/*
 * HANDLER: em_config_channel_scan
 *
 * Copied VERBATIM from OneWifi source/apps/em/wifi_em.c (only "static"
 * dropped). Local arrays:
 *   - mac_address_t radio_mac (uchar[6])  : mac_address_from_name.
 *   - mac_addr_str_t mac_str (char[18])   : bounded to_mac_str.
 * The input length is validated (len >= sizeof(channel_scan_request_t)) before
 * the cast, the only read of scan_req is its 6-byte ruid (memcmp), and the loop
 * is bounded by the 8-entry radio_interface_map. No array can be overrun ->
 * SAFE. (void return type -- no missing-return concern.)
 *
 * Scaffolding (NOT under test): get_wifimgr_obj / mac_address_from_name /
 * to_mac_str / em_process_scan_init_command are stubbed and driven by the
 * eccs_* globals.
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

/* --- scaffolding stubs driven by eccs_* globals --- */
static wifi_mgr_t *get_wifimgr_obj(void) { return eccs_mgr_null ? NULL : (wifi_mgr_t *)eccs_mgr_buf; }
static int mac_address_from_name(const char *name, mac_addr_t mac)
{
    for (int i = 0; i < eccs_iface_count; i++)
        if (strcmp(name, eccs_iface_name[i]) == 0) { memcpy(mac, eccs_iface_mac[i], 6); return RETURN_OK; }
    memset(mac, 0, 6);
    return RETURN_OK;
}
static char *to_mac_str(mac_address_t mac, mac_addr_str_t key)
{
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}
static void em_process_scan_init_command(int radio_index, channel_scan_request_t *scan_req)
{
    (void)scan_req;
    eccs_scan_init_calls++;
    eccs_scan_init_radio = radio_index;
}

/* ================= VERBATIM from wifi_em.c (static dropped) ================= */
void em_config_channel_scan(void *data, unsigned int len)
{
    mac_address_t radio_mac;
    mac_addr_str_t mac_str;
    radio_interface_mapping_t *radio_iface_map = NULL;
    channel_scan_request_t *scan_req;
    wifi_mgr_t *mgr;
    wifi_platform_property_t *wifi_prop;

    if (data == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d NUll data Pointer\n", __func__, __LINE__);
        return;
    }

    if (len < sizeof(channel_scan_request_t)) {
        wifi_util_error_print(WIFI_EM, "%s:%d Invalid parameter size \r\n", __func__, __LINE__);
        return;
    }

    mgr = get_wifimgr_obj();
    if (mgr == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d Mgr object is NULL \r\n", __func__, __LINE__);
        return;
    }

    wifi_prop = &mgr->hal_cap.wifi_prop;
    scan_req = (channel_scan_request_t *)data;

    for (unsigned int k = 0;
         k < (sizeof(wifi_prop->radio_interface_map) / sizeof(radio_interface_mapping_t)); k++) {
        radio_iface_map = &(wifi_prop->radio_interface_map[k]);
        if (radio_iface_map == NULL) {
            printf("%s:%d: Unable to find the radio interface map entry \n", __func__, __LINE__);
            return;
        }
        mac_address_from_name(radio_iface_map->interface_name, radio_mac);
        if (memcmp(scan_req->ruid, radio_mac, sizeof(mac_addr_t)) == 0) {
            wifi_util_dbg_print(WIFI_EM, "%s:%d Processing channel scan for Radio : %s\n", __func__,
                __LINE__, to_mac_str(radio_mac, mac_str));
            em_process_scan_init_command(wifi_prop->radio_interface_map[k].radio_index, scan_req);
            break;
        }
    }
}
