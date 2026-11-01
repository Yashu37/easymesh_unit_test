/*
 * TEST CASES / CONSTRUCTOR: construct_is_blaster_device_associated
 *
 * sta_mac is MAC_ADDR_LEN bytes at the start of bib_mac_buf, is_mlo is one
 * bool at the start of bib_mlo_buf, the vap info and the station are at the
 * start of their own buffers (bytes past each poisoned by the runner).
 *
 * Cases: no vap info, NULL associated_devices_map, station not in the map,
 * station found with is_mlo NULL, is_mlo false -> takes cli_MLDEnable,
 * is_mlo already true (kept), MAC with hex letters (lower-case key), and
 * ff:ff:.. (key is exactly 17 chars + NUL = STA_KEY_LEN).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

char   bib_slot_key[BIB_KEY_SZ + BIB_PAD];
size_t bib_key_len;
char   bib_key_seen[64];
char   bib_sta_key[32];
int    bib_vap_lookups, bib_lookup_index;
rdk_wifi_vap_info_t *bib_vap;
assoc_dev_data_t    *bib_sta;
alignas(16) unsigned char bib_mac_buf[MAC_ADDR_LEN + BIB_PAD];
alignas(16) char bib_mlo_buf[sizeof(bool) + BIB_PAD];
alignas(16) char bib_vap_buf[sizeof(rdk_wifi_vap_info_t) + BIB_PAD];
alignas(16) char bib_sta_buf[sizeof(assoc_dev_data_t) + BIB_PAD];
static pthread_mutex_t bib_lock = PTHREAD_MUTEX_INITIALIZER;

is_blaster_device_associated_test_case_t is_blaster_device_associated_suite[] = {
    /* name             no_vap no_map in_map mlo_null mlo_in mld  mac0  ret   mlo_out */
    { "no_vap_info",      1,     0,     0,     0,      0,    0,  0x10, false, 0 },
    { "null_map",         0,     1,     0,     0,      0,    0,  0x10, false, 0 },
    { "sta_not_found",    0,     0,     0,     0,      0,    1,  0x10, false, 0 },
    { "found_mlo_null",   0,     0,     1,     1,      0,    1,  0x10, true,  0 },
    { "found_takes_mld",  0,     0,     1,     0,      0,    1,  0x10, true,  1 },
    { "found_mlo_kept",   0,     0,     1,     0,      1,    0,  0x10, true,  1 },
    { "mac_hex_letters",  0,     0,     1,     0,      0,    0,  0xaa, true,  0 },
    { "mac_all_ff",       0,     0,     1,     0,      0,    1,  0xff, true,  1 },

    { NULL, 0, 0, 0, 0, 0, 0, 0, false, 0 }  /* sentinel */
};

void construct_is_blaster_device_associated_input(const is_blaster_device_associated_test_case_t *tc)
{
    memset(bib_mac_buf, 0, sizeof(bib_mac_buf));
    memset(bib_mlo_buf, 0, sizeof(bib_mlo_buf));
    memset(bib_vap_buf, 0, sizeof(bib_vap_buf));
    memset(bib_sta_buf, 0, sizeof(bib_sta_buf));
    for (int b = 0; b < MAC_ADDR_LEN; b++)
        bib_mac_buf[b] = (tc->mac0 == 0xff) ? 0xff : (unsigned char)(tc->mac0 + b);
    snprintf(bib_sta_key, sizeof(bib_sta_key), "%02x:%02x:%02x:%02x:%02x:%02x",
             bib_mac_buf[0], bib_mac_buf[1], bib_mac_buf[2], bib_mac_buf[3], bib_mac_buf[4], bib_mac_buf[5]);
    *(bool *)bib_mlo_buf = tc->mlo_in ? true : false;

    rdk_wifi_vap_info_t *v = (rdk_wifi_vap_info_t *)bib_vap_buf;
    v->vap_index = 3;
    v->associated_devices_lock = &bib_lock;
    v->associated_devices_map = tc->no_map ? NULL : (void *)0x1;   /* only passed to the stub */
    bib_vap = tc->no_vap ? NULL : v;

    assoc_dev_data_t *s = (assoc_dev_data_t *)bib_sta_buf;
    s->dev_stats.cli_MLDEnable = tc->mld ? true : false;
    bib_sta = tc->in_map ? s : NULL;

    bib_key_len = 0;
    bib_key_seen[0] = 0;
    bib_vap_lookups = 0;
    bib_lookup_index = -1;
}
