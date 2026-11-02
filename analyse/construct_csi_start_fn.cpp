/*
 * TEST CASES / CONSTRUCTOR: construct_csi_start_fn
 * mac_addr is 6 bytes at csf_mac_buf (poison past 6). The rdk_vap, the csi
 * app, the assoc-map entry, the csi-map entry and an eviction victim are set
 * per case. associated_devices_map = 0x2, csi_sounding_mac_map = 0x1 so the
 * hash_map_get stub returns the right object.
 * Cases: app NULL, vap NULL, map NULL, new entry, MLO entry, eviction (motion).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

char   csf_slot_mac[CSF_MAC_SZ + CSF_PAD];
char   csf_put_key[64];
void  *csf_put_data;
int    csf_put_calls, csf_remove_calls;
wifi_app_t *csf_app;
rdk_wifi_vap_info_t *csf_vap;
void  *csf_assoc, *csf_csi_entry, *csf_victim;
alignas(16) char csf_app_buf[sizeof(wifi_app_t) + CSF_PAD];
alignas(16) char csf_vap_buf[sizeof(rdk_wifi_vap_info_t) + CSF_PAD];
alignas(16) unsigned char csf_mac_buf[6 + CSF_PAD];
static pthread_mutex_t csf_lock = PTHREAD_MUTEX_INITIALIZER;
static assoc_dev_data_t csf_assoc_obj;
static csi_mac_data_t   csf_victim_obj;

csi_start_fn_test_case_t csi_start_fn_suite[] = {
    /* name        app_null vap_null map_null mlo  evict  sounding_app  mac0  ret */
    { "app_null",    1,      0,       0,       0,   0,     1,            0x10, -1 },
    { "vap_null",    0,      1,       0,       0,   0,     1,            0x10, -1 },
    { "map_null",    0,      0,       1,       0,   0,     1,            0x10, -1 },
    { "new_entry",   0,      0,       0,       0,   0,     1,            0x10,  0 },
    { "mlo_entry",   0,      0,       0,       1,   0,     1,            0x10,  0 },
    { "eviction",    0,      0,       0,       0,   1,     0x20,         0x10,  0 },
    { NULL, 0, 0, 0, 0, 0, 0, 0, 0 }
};

void construct_csi_start_fn_input(const csi_start_fn_test_case_t *tc)
{
    memset(csf_app_buf, 0, sizeof(csf_app_buf));
    memset(csf_vap_buf, 0, sizeof(csf_vap_buf));
    memset(csf_mac_buf, 0, sizeof(csf_mac_buf));
    for (int b = 0; b < 6; b++) csf_mac_buf[b] = (unsigned char)(tc->mac0 + b);

    wifi_app_t *app = (wifi_app_t *)csf_app_buf;
    app->data.u.csi.csi_sounding_mac_map = tc->map_null ? NULL : (void *)0x1;
    app->data.u.csi.num_current_sounding = tc->evict ? 5 : 0;   /* >= MAX for eviction */
    csf_app = app;   /* set via extern below */

    rdk_wifi_vap_info_t *v = (rdk_wifi_vap_info_t *)csf_vap_buf;
    v->associated_devices_lock = &csf_lock;
    v->associated_devices_map = (void *)0x2;
    csf_vap = tc->vap_null ? NULL : v;

    memset(&csf_assoc_obj, 0, sizeof(csf_assoc_obj));
    if (tc->mlo) {
        csf_assoc_obj.dev_stats.cli_MLDEnable = true;
        csf_assoc_obj.association_link = true;
        for (int b = 0; b < 6; b++) csf_assoc_obj.link_address[b] = 0xD0 + b;
        csf_assoc = &csf_assoc_obj;
    } else {
        csf_assoc = NULL;
    }
    csf_csi_entry = NULL;   /* no existing csi entry -> new */

    memset(&csf_victim_obj, 0, sizeof(csf_victim_obj));
    csf_victim_obj.subscribed_apps = 1;   /* non-motion -> evictable */
    csf_victim_obj.ap_index = 7;
    for (int b = 0; b < 6; b++) { csf_victim_obj.mac_addr[b] = 0xB0 + b; csf_victim_obj.link_addr[b] = 0xC0 + b; }
    csf_victim = tc->evict ? &csf_victim_obj : NULL;

    csf_put_key[0] = 0; csf_put_data = NULL; csf_put_calls = 0; csf_remove_calls = 0;
}
