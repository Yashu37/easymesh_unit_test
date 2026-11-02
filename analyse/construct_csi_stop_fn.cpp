/*
 * TEST CASES / CONSTRUCTOR: construct_csi_stop_fn
 * mac_addr 6 bytes at csp_mac_buf (poison past 6). The map entry can be found
 * directly (csp_entry) or via MLD match (csp_first), with subscribed_apps set
 * to one app (disable+remove) or several (keep). app/map can be NULL.
 * Cases: app NULL, map NULL, found+more-apps (keep), found+single (remove),
 * not-found MLD match (remove), not-found no match.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

char   csp_slot_mac[CSP_MAC_SZ + CSP_PAD];
char   csp_key_seen[64];
wifi_app_t *csp_app;
void  *csp_entry, *csp_first;
int    csp_remove_calls;
alignas(16) char csp_app_buf[sizeof(wifi_app_t) + CSP_PAD];
alignas(16) unsigned char csp_mac_buf[6 + CSP_PAD];
static csi_mac_data_t csp_obj, csp_first_obj;

csi_stop_fn_test_case_t csi_stop_fn_suite[] = {
    /* name          app_null map_null found  first_match  sub_apps sounding mac0  ret expect_remove */
    { "app_null",      1,      0,       0,     0,           1,       1,       0x10, -1, 0 },
    { "map_null",      0,      1,       0,     0,           1,       1,       0x10, -1, 0 },
    { "found_more",    0,      0,       1,     0,           3,       1,       0x10,  0, 0 },  /* 3 has other bits */
    { "found_single",  0,      0,       1,     0,           1,       1,       0x10,  0, 1 },
    { "mld_match",     0,      0,       0,     1,           1,       1,       0x10,  0, 1 },
    { "no_match",      0,      0,       0,     0,           1,       1,       0x10,  0, 0 },
    { NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};

void construct_csi_stop_fn_input(const csi_stop_fn_test_case_t *tc)
{
    memset(csp_app_buf, 0, sizeof(csp_app_buf));
    memset(csp_mac_buf, 0, sizeof(csp_mac_buf));
    for (int b = 0; b < 6; b++) csp_mac_buf[b] = (unsigned char)(tc->mac0 + b);

    wifi_app_t *app = (wifi_app_t *)csp_app_buf;
    app->data.u.csi.csi_sounding_mac_map = tc->map_null ? NULL : (void *)0x1;
    app->data.u.csi.num_current_sounding = 3;
    csp_app = app;

    memset(&csp_obj, 0, sizeof(csp_obj));
    csp_obj.subscribed_apps = tc->sub_apps; csp_obj.ap_index = 5;
    for (int b = 0; b < 6; b++) csp_obj.mac_addr[b] = (unsigned char)(tc->mac0 + b);
    csp_entry = tc->found ? &csp_obj : NULL;

    memset(&csp_first_obj, 0, sizeof(csp_first_obj));
    csp_first_obj.subscribed_apps = tc->sub_apps; csp_first_obj.ap_index = 6;
    /* MLD match: first entry's mac_addr equals the query mac */
    for (int b = 0; b < 6; b++) csp_first_obj.mac_addr[b] = tc->first_match ? (unsigned char)(tc->mac0 + b) : 0xEE;
    for (int b = 0; b < 6; b++) csp_first_obj.link_addr[b] = 0xC0 + b;
    csp_first = (tc->first_match || !tc->found) ? &csp_first_obj : NULL;

    csp_key_seen[0] = 0; csp_remove_calls = 0;
}
