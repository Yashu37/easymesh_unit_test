/*
 * TEST CASES / CONSTRUCTOR: construct_em_get_vap_index_from_bssid
 *
 * Fixed topology: 2 radios, 2 vaps each. vap_index 0,1 (radio 0, bssids AA,BB)
 * and 2,3 (radio 1, bssids CC,DD). The query BSSID lives in evb_bssid_buf;
 * the runner poisons past its 6 bytes.
 *
 * Cases: match a non-mesh vap bssid (-> its vap_index), a bssid that matches a
 * vap flagged STA-mesh (skipped -> RETURN_ERR), and no match (-> RETURN_ERR).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

int  evb_num_radios;
alignas(16) unsigned char evb_bssid_buf[6 + EVB_PAD];
int  evb_vap_present[8];
wifi_vap_info_map_t evb_vap_maps[8];
int  evb_mesh_vap[64];

em_gvb_test_case_t em_get_vap_index_from_bssid_suite[] = {
    /* name            want_ret */
    { "match_vap",       2 },    /* bssid CC.. = radio1 vap_index 2 (not mesh) */
    { "mesh_skipped",   -1 },    /* bssid AA.. = vap_index 0 but flagged mesh  */
    { "no_match",       -1 },    /* bssid FF.. matches nothing                 */
    { NULL, 0 }  /* sentinel */
};

static void set_vap(int radio, int slot, unsigned int vi, unsigned char b0)
{
    evb_vap_maps[radio].num_vaps = 2;
    evb_vap_maps[radio].vap_array[slot].vap_index = vi;
    unsigned char *d = evb_vap_maps[radio].vap_array[slot].u.bss_info.bssid;
    d[0] = b0; d[1] = 0xbb; d[2] = 0xcc; d[3] = 0xdd; d[4] = 0xee; d[5] = 0xff;
}

void construct_em_get_vap_index_from_bssid_input(const em_gvb_test_case_t *tc)
{
    memset(evb_vap_maps, 0, sizeof(evb_vap_maps));
    memset(evb_mesh_vap, 0, sizeof(evb_mesh_vap));
    memset(evb_bssid_buf, 0, sizeof(evb_bssid_buf));
    evb_num_radios = 2;
    evb_vap_present[0] = 1; evb_vap_present[1] = 1;

    set_vap(0, 0, 0, 0xAA); set_vap(0, 1, 1, 0xBB);
    set_vap(1, 0, 2, 0xCC); set_vap(1, 1, 3, 0xDD);

    if (strcmp(tc->test_name, "match_vap") == 0) {
        unsigned char q[6] = {0xCC,0xbb,0xcc,0xdd,0xee,0xff}; memcpy(evb_bssid_buf, q, 6);
    } else if (strcmp(tc->test_name, "mesh_skipped") == 0) {
        evb_mesh_vap[0] = 1;   /* vap_index 0 is STA mesh -> skipped */
        unsigned char q[6] = {0xAA,0xbb,0xcc,0xdd,0xee,0xff}; memcpy(evb_bssid_buf, q, 6);
    } else {
        unsigned char q[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}; memcpy(evb_bssid_buf, q, 6);
    }
}
