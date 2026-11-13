/*
 * TEST CASES / CONSTRUCTOR: construct_bstamld_get_inner
 *
 * event_name lives in name_store at offset BML_LEFT (runner poisons the bytes in front of it and past its
 * NUL). One device 1 (or MAC alias 02:00:00:00:00:01) with the bSTA MLD info: MLD MAC 02:00:00:00:00:a1,
 * AP MLD MAC (BSSID) 02:00:00:00:00:b1, affiliated bSTA i has MAC 02:00:00:00:01:<i hex>; the runner poisons
 * the members after affiliated_bsta[64]. Knobs: n_aff, mld_valid / bssid_valid (invalid -> zero MAC), no_bsta.
 *
 * expect_rc: 0 success, 2 invalid_input, 25 invalid_namespace, 100 destination_not_found (stand-in value).
 * Cases marked [spec] are wrong behaviour (no abort): Device.1abc read as 1 by atoi; with num_affiliated_bsta
 * above 14 the string holds the first 14 MACs followed by a stray ',' (maclist_to_string() gets the uncapped
 * count). The crash_* cases (method name shorter than the Network prefix, path without a Device instance)
 * ABORT on the original handler: they run last and UNFORKED (a plain make stops at the first ASan report);
 * FORK_CRASH=1 runs each in a forked child so all of them show.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bstamld_get_inner.h"

namespace bml {

alignas(16) char name_store[BML_LEFT + BML_NAME_SZ + BML_PAD];

/* {name, event, no_pdata, no_dm, no_bsta, mld_valid, bssid_valid, n_aff, expect_rc, expect_val, crash} */
test_case_t suite[] = {
 /* ---- MLD MAC / BSSID ---- */
 {"ok_mld_mac", "Device.WiFi.DataElements.Network.Device.1.MLDMACAddress", false, false, false, true, true, 0, 0, "02:00:00:00:00:a1", false},
 {"ok_mld_mac_invalid_zero", "Device.WiFi.DataElements.Network.Device.1.MLDMACAddress", false, false, false, false, true, 0, 0, "00:00:00:00:00:00", false},
 {"ok_bssid", "Device.WiFi.DataElements.Network.Device.1.BSSID", false, false, false, true, true, 0, 0, "02:00:00:00:00:b1", false},
 {"ok_bssid_invalid_zero", "Device.WiFi.DataElements.Network.Device.1.BSSID", false, false, false, true, false, 0, 0, "00:00:00:00:00:00", false},
 {"ok_alias_path", "Device.WiFi.DataElements.Network.Device.[02:00:00:00:00:01].MLDMACAddress", false, false, false, true, true, 0, 0, "02:00:00:00:00:a1", false},
 /* ---- affiliated bSTA list ---- */
 {"ok_list_empty", "Device.WiFi.DataElements.Network.Device.1.AffiliatedbSTAList", false, false, false, true, true, 0, 0, "", false},
 {"ok_list_1", "Device.WiFi.DataElements.Network.Device.1.AffiliatedbSTAList", false, false, false, true, true, 1, 0, "02:00:00:00:01:00", false},
 {"ok_list_2", "Device.WiFi.DataElements.Network.Device.1.AffiliatedbSTAList", false, false, false, true, true, 2, 0, "02:00:00:00:01:00,02:00:00:00:01:01", false},
 {"ok_list_3", "Device.WiFi.DataElements.Network.Device.1.AffiliatedbSTAList", false, false, false, true, true, 3, 0, "02:00:00:00:01:00,02:00:00:00:01:01,02:00:00:00:01:02", false},
 {"ok_list_13", "Device.WiFi.DataElements.Network.Device.1.AffiliatedbSTAList", false, false, false, true, true, 13, 0, "02:00:00:00:01:00,02:00:00:00:01:01,02:00:00:00:01:02,02:00:00:00:01:03,02:00:00:00:01:04,02:00:00:00:01:05,02:00:00:00:01:06,02:00:00:00:01:07,02:00:00:00:01:08,02:00:00:00:01:09,02:00:00:00:01:0a,02:00:00:00:01:0b,02:00:00:00:01:0c", false},
 {"ok_list_14_full", "Device.WiFi.DataElements.Network.Device.1.AffiliatedbSTAList", false, false, false, true, true, 14, 0, "02:00:00:00:01:00,02:00:00:00:01:01,02:00:00:00:01:02,02:00:00:00:01:03,02:00:00:00:01:04,02:00:00:00:01:05,02:00:00:00:01:06,02:00:00:00:01:07,02:00:00:00:01:08,02:00:00:00:01:09,02:00:00:00:01:0a,02:00:00:00:01:0b,02:00:00:00:01:0c,02:00:00:00:01:0d", false},
 /* ---- rejected ---- */
 {"rej_invalid_param", "Device.WiFi.DataElements.Network.Device.1.Foo", false, false, false, true, true, 0, 100, NULL, false},
 {"rej_no_bsta_mld", "Device.WiFi.DataElements.Network.Device.1.MLDMACAddress", false, false, true, true, true, 0, 100, NULL, false},
 {"rej_device_not_found", "Device.WiFi.DataElements.Network.Device.9.MLDMACAddress", false, false, false, true, true, 0, 25, NULL, false},
 {"rej_device_alias_not_found", "Device.WiFi.DataElements.Network.Device.[aa:bb:cc:dd:ee:ff].MLDMACAddress", false, false, false, true, true, 0, 25, NULL, false},
 {"rej_no_dm", "Device.WiFi.DataElements.Network.Device.1.MLDMACAddress", false, true, false, true, true, 0, 25, NULL, false},
 {"rej_event_null", NULL, false, false, false, true, true, 0, 2, NULL, false},
 {"rej_pdata_null", "Device.WiFi.DataElements.Network.Device.1.MLDMACAddress", true, false, false, true, true, 0, 2, NULL, false},
 {"rej_no_dot", "MLDMACAddress", false, false, false, true, true, 0, 2, NULL, false},
 /* ---- [spec]: wrong behaviour, no abort ---- */
 {"spec_device_1abc [spec]", "Device.WiFi.DataElements.Network.Device.1abc.MLDMACAddress", false, false, false, true, true, 0, 25, NULL, false},
 {"spec_list_15_trailing_comma [spec]", "Device.WiFi.DataElements.Network.Device.1.AffiliatedbSTAList", false, false, false, true, true, 15, 0, "02:00:00:00:01:00,02:00:00:00:01:01,02:00:00:00:01:02,02:00:00:00:01:03,02:00:00:00:01:04,02:00:00:00:01:05,02:00:00:00:01:06,02:00:00:00:01:07,02:00:00:00:01:08,02:00:00:00:01:09,02:00:00:00:01:0a,02:00:00:00:01:0b,02:00:00:00:01:0c,02:00:00:00:01:0d", false},
 {"spec_list_64_trailing_comma [spec]", "Device.WiFi.DataElements.Network.Device.1.AffiliatedbSTAList", false, false, false, true, true, 64, 0, "02:00:00:00:01:00,02:00:00:00:01:01,02:00:00:00:01:02,02:00:00:00:01:03,02:00:00:00:01:04,02:00:00:00:01:05,02:00:00:00:01:06,02:00:00:00:01:07,02:00:00:00:01:08,02:00:00:00:01:09,02:00:00:00:01:0a,02:00:00:00:01:0b,02:00:00:00:01:0c,02:00:00:00:01:0d", false},
 {"spec_list_255_trailing_comma [spec]", "Device.WiFi.DataElements.Network.Device.1.AffiliatedbSTAList", false, false, false, true, true, 255, 0, "02:00:00:00:01:00,02:00:00:00:01:01,02:00:00:00:01:02,02:00:00:00:01:03,02:00:00:00:01:04,02:00:00:00:01:05,02:00:00:00:01:06,02:00:00:00:01:07,02:00:00:00:01:08,02:00:00:00:01:09,02:00:00:00:01:0a,02:00:00:00:01:0b,02:00:00:00:01:0c,02:00:00:00:01:0d", false},
 /* ---- CRASH cases (run last, unforked) ---- */
 {"crash_method_short", "X.MLDMACAddress", false, false, false, true, true, 0, 2, NULL, true},
 {"crash_path_without_device", "Device.WiFi.DataElements.Network.MLDMACAddress", false, false, false, true, true, 0, 2, NULL, true},

 { NULL, NULL, false, false, false, false, false, 0, 0, NULL, false }  /* sentinel */
};

void construct_input(const test_case_t *tc)
{
    memset(name_store, 0, sizeof(name_store));
    if (tc->event) snprintf(name_store + BML_LEFT, BML_NAME_SZ, "%s", tc->event);
    g_nset = 0; g_val[0] = '\0'; g_dm = NULL;
    if (tc->no_dm) return;
    dm_easy_mesh_t *dm = new dm_easy_mesh_t;
    memset((void *)dm, 0, sizeof(*dm));
    dm->bsta = !tc->no_bsta;
    em_bsta_mld_info_t *b = &dm->bsm;
    unsigned char a1[6] = {2, 0, 0, 0, 0, 0xa1}, b1[6] = {2, 0, 0, 0, 0, 0xb1};
    b->mac_addr_valid = tc->mld_valid; b->ap_mld_mac_addr_valid = tc->bssid_valid;
    memcpy(b->mac_addr, a1, 6); memcpy(b->ap_mld_mac_addr, b1, 6);
    b->num_affiliated_bsta = (unsigned char)tc->n_aff;
    for (int i = 0; i < BML_MAXAFF; i++) {
        unsigned char m[6] = {2, 0, 0, 0, 1, (unsigned char)i};
        memcpy(b->affiliated_bsta[i].mac_addr, m, 6);
        b->affiliated_bsta[i].mac_addr_valid = true;
    }
    g_dm = dm;
}

void teardown(void)
{
    delete g_dm; g_dm = NULL;
}

} /* namespace bml */
