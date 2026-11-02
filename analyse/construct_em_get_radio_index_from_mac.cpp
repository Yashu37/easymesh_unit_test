/*
 * TEST CASES / CONSTRUCTOR: construct_em_get_radio_index_from_mac
 *
 * Fixed topology: 2 radios. Radio 0 has 2 vaps (bssids AA.., BB..), radio 1
 * has 2 vaps (CC.., DD..). The radio_interface_map maps iface "wlan0"->radio 0
 * (mac 10..) and "wlan1"->radio 1 (mac 20..). The query MAC (ruuid) lives in
 * erm_ruuid_buf; the runner poisons past its 6 bytes.
 *
 * Cases: match a vap bssid (-> that radio_index), match a radio interface MAC
 * (-> that radio index), and no match anywhere (-> RETURN_ERR).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

int  erm_num_radios;
alignas(16) char erm_mgr_buf[sizeof(wifi_mgr_t) + ERM_PAD];
alignas(16) unsigned char erm_ruuid_buf[6 + ERM_PAD];
int  erm_vap_present[8];
wifi_vap_info_map_t erm_vap_maps[8];
int  erm_iface_count;
char erm_iface_name[8][32];
unsigned char erm_iface_mac[8][6];

em_gri_test_case_t em_get_radio_index_from_mac_suite[] = {
    /* name              want_ret */
    { "match_vap_bssid",   1 },   /* ruuid = radio1 vap0 bssid CC.. -> radio_index 1 */
    { "match_radio_iface", 0 },   /* ruuid = wlan0 iface mac 10..   -> radio 0        */
    { "no_match",         -1 },   /* ruuid = FF..                   -> RETURN_ERR      */
    { NULL, 0 }  /* sentinel */
};

static void set_bssid(int radio, int vap, int ri, unsigned char b0)
{
    erm_vap_maps[radio].num_vaps = 2;
    erm_vap_maps[radio].vap_array[vap].radio_index = ri;
    unsigned char *d = erm_vap_maps[radio].vap_array[vap].u.bss_info.bssid;
    d[0] = b0; d[1] = 0xbb; d[2] = 0xcc; d[3] = 0xdd; d[4] = 0xee; d[5] = 0xff;
}

void construct_em_get_radio_index_from_mac_input(const em_gri_test_case_t *tc)
{
    memset(erm_mgr_buf, 0, sizeof(erm_mgr_buf));
    memset(erm_vap_maps, 0, sizeof(erm_vap_maps));
    memset(erm_ruuid_buf, 0, sizeof(erm_ruuid_buf));
    erm_num_radios = 2;
    erm_vap_present[0] = 1; erm_vap_present[1] = 1;

    /* radio 0: bssids 0xAA.., 0xBB..   radio 1: 0xCC.., 0xDD.. */
    set_bssid(0, 0, 0, 0xAA); set_bssid(0, 1, 0, 0xBB);
    set_bssid(1, 0, 1, 0xCC); set_bssid(1, 1, 1, 0xDD);

    /* interface map in the wifi_prop: wlan0->radio0 (10..), wlan1->radio1 (20..) */
    wifi_mgr_t *m = (wifi_mgr_t *)erm_mgr_buf;
    wifi_platform_property_t *wp = &m->hal_cap.wifi_prop;
    memset(wp->radio_interface_map, 0, sizeof(wp->radio_interface_map));
    for (int k = 2; k < 8; k++) wp->radio_interface_map[k].radio_index = -1;  /* unused slots */
    snprintf(wp->radio_interface_map[0].interface_name, 32, "wlan0"); wp->radio_interface_map[0].radio_index = 0;
    snprintf(wp->radio_interface_map[1].interface_name, 32, "wlan1"); wp->radio_interface_map[1].radio_index = 1;
    erm_iface_count = 2;
    snprintf(erm_iface_name[0], 32, "wlan0"); unsigned char m0[6] = {0x10,0x11,0x12,0x13,0x14,0x15}; memcpy(erm_iface_mac[0], m0, 6);
    snprintf(erm_iface_name[1], 32, "wlan1"); unsigned char m1[6] = {0x20,0x21,0x22,0x23,0x24,0x25}; memcpy(erm_iface_mac[1], m1, 6);

    /* pick the query MAC per case */
    if (strcmp(tc->test_name, "match_vap_bssid") == 0) {
        unsigned char q[6] = {0xCC,0xbb,0xcc,0xdd,0xee,0xff}; memcpy(erm_ruuid_buf, q, 6);   /* radio1 vap0 bssid */
    } else if (strcmp(tc->test_name, "match_radio_iface") == 0) {
        memcpy(erm_ruuid_buf, m0, 6);   /* wlan0 iface mac -> radio 0 */
    } else {
        unsigned char q[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}; memcpy(erm_ruuid_buf, q, 6);
    }
}
