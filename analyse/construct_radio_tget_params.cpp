/*
 * TEST CASES / CONSTRUCTOR: construct_radio_tget_params
 *
 * root (the path prefix handed to radio_tget_params) lives in root_store at offset RTP_LEFT (the runner
 * poisons the bytes in front of it and past its NUL); root "LONG" is expanded to a 600-character prefix.
 * One data model: radios 1..3 with RUID 02:00:00:00:00:r, enabled, noise 90, utilization 12, transmit 3,
 * receive_self 4, receive_other 5, vendor "Vend", temperature 55; op classes filled in order
 * (cur[r] current + cap[r] capability entries per radio); radio cap entries per has_cap bit (mode
 * as given, HT streams 2/2 gi20 ht40 -> "Wg==", VHT mcs 0xfffa streams 2/2 gi80 160mhz su -> "//r/+iZg");
 * backhaul sta 02:00:00:00:00:aa when bh is set.
 *
 * Expected: always bus_error_success (0). Cases marked [spec] are wrong behaviour. The crash_* cases
 * (m_num_opclass above the 64-entry m_op_class[], m_num_radios above the 3-entry m_radio_cap[] with a radio
 * that has no cap entry) ABORT on the original handler: they run last and UNFORKED (a plain make stops at
 * the first ASan report); FORK_CRASH=1 runs each in a forked child so all of them show.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "radio_tget_params.h"

namespace rtp {

#define RTP_LEFT 16
alignas(16) char root_store[RTP_LEFT + RTP_ROOT_SZ + 64];
const char *root_ptr = NULL;

#define R "Device.WiFi.DataElements.Network.Device.1.Radio."
#define ALLM (0x01|0x02|0x04|0x08|0x10|0x20|0x40|0x80)
#define MODE_ANAC (0x01|0x08|0x10)
/* {name, root, n_radios, n_oc, cur[3], cap[3], has_cap, nbss, bh, mode, expect_ids, has, not_has, crash} */
#define T(n, nr, c0,c1,c2, p0,p1,p2, hc, nbss, bh, mode, ids, has, nh) {n, R, nr, -1, {c0,c1,c2}, {p0,p1,p2}, hc, nbss, bh, mode, ids, has, nh, false}

test_case_t suite[] = {
 /* ---- ID / plain radio values ---- */
 T("ok_id_radio1", 1, 0,0,0, 0,0,0, 0, 1, false, 0, 1, "1:ID=AgAAAAAB\n", NULL),
 T("ok_id_radio2", 2, 0,0,0, 0,0,0, 0, 1, false, 0, 2, "2:ID=AgAAAAAC\n", NULL),
 T("ok_id_radio3", 3, 0,0,0, 0,0,0, 0, 1, false, 0, 3, "3:ID=AgAAAAAD\n", NULL),
 T("ok_enabled", 1, 0,0,0, 0,0,0, 0, 1, false, 0, 1, "1:Enabled=1\n", NULL),
 T("ok_noise", 1, 0,0,0, 0,0,0, 0, 1, false, 0, 1, "1:Noise=90\n", NULL),
 T("ok_utilization", 1, 0,0,0, 0,0,0, 0, 1, false, 0, 1, "1:Utilization=12\n", NULL),
 T("ok_transmit", 1, 0,0,0, 0,0,0, 0, 1, false, 0, 1, "1:Transmit=3\n", NULL),
 T("ok_receive_self", 1, 0,0,0, 0,0,0, 0, 1, false, 0, 1, "1:ReceiveSelf=4\n", NULL),
 T("ok_receive_other", 1, 0,0,0, 0,0,0, 0, 1, false, 0, 1, "1:ReceiveOther=5\n", NULL),
 T("ok_chipset_vendor", 1, 0,0,0, 0,0,0, 0, 1, false, 0, 1, "1:ChipsetVendor=Vend\n", NULL),
 T("ok_temperature", 1, 0,0,0, 0,0,0, 0, 1, false, 0, 1, "1:X_AIRTIES_Temperature=55\n", NULL),
 T("ok_bss_entries", 1, 0,0,0, 0,0,0, 0, 3, false, 0, 1, "1:BSSNumberOfEntries=3\n", NULL),
 /* ---- how many radios ---- */
 T("ok_no_radios", 0, 0,0,0, 0,0,0, 0, 1, false, 0, 0, NULL, "ID="),
 T("ok_two_radios", 2, 0,0,0, 0,0,0, 0, 1, false, 0, 2, NULL, "3:ID="),
 T("ok_radios_clamped_to_3", 5, 0,0,0, 0,0,0, 7, 1, false, 0, 3, NULL, "4:ID="),
 /* ---- operating class counts ---- */
 T("ok_curop_count_2", 1, 2,0,0, 0,0,0, 0, 1, false, 0, 1, "1:CurrentOperatingClassProfileNumberOfEntries=2\n", NULL),
 T("ok_curop_count_radio2", 2, 2,1,0, 0,0,0, 0, 1, false, 0, 2, "2:CurrentOperatingClassProfileNumberOfEntries=1\n", NULL),
 T("ok_curop_ignores_capability", 1, 1,0,0, 3,0,0, 0, 1, false, 0, 1, "1:CurrentOperatingClassProfileNumberOfEntries=1\n", NULL),
 T("ok_curop_ignores_other_radio", 1, 0,4,0, 0,0,0, 0, 1, false, 0, 1, "1:CurrentOperatingClassProfileNumberOfEntries=0\n", NULL),
 T("ok_curop_count_full_64", 1, 64,0,0, 0,0,0, 0, 1, false, 0, 1, "1:CurrentOperatingClassProfileNumberOfEntries=64\n", NULL),
 T("ok_capop_count_cap_present", 1, 0,0,0, 3,0,0, 1, 1, false, 0, 1, "1:Capabilities.CapableOperatingClassProfileNumberOfEntries=3\n", NULL),
 T("ok_capop_count_cap_absent", 1, 0,0,0, 2,0,0, 0, 1, false, 0, 1, "1:Capabilities.CapableOperatingClassProfileNumberOfEntries=2\n", NULL),
 /* ---- backhaul sta ---- */
 T("ok_bh_sta_4bss", 1, 0,0,0, 0,0,0, 0, 4, true, 0, 1, "1:BackhaulSta.MACAddress=02:00:00:00:00:aa\n", NULL),
 T("ok_bh_sta_not_4bss_hidden", 1, 0,0,0, 0,0,0, 0, 2, true, 0, 1, "1:BackhaulSta.MACAddress=\n", "=02:00:00:00:00:aa"),
 T("ok_no_bh_sta", 1, 0,0,0, 0,0,0, 0, 4, false, 0, 1, "1:BackhaulSta.MACAddress=\n", "=02:00:00:00:00:aa"),
 /* ---- radio capabilities ---- */
 T("ok_cap_standards", 1, 0,0,0, 0,0,0, 1, 1, false, MODE_ANAC, 1, "1:X_AIRTIES_OperatingStandards=a,n,ac\n", NULL),
 T("ok_cap_standards_all", 1, 0,0,0, 0,0,0, 1, 1, false, ALLM, 1, "1:X_AIRTIES_OperatingStandards=a,b,g,n,ac,ax,be,bn\n", NULL),
 T("ok_cap_standards_none", 1, 0,0,0, 0,0,0, 1, 1, false, 0, 1, "1:X_AIRTIES_OperatingStandards=\n", NULL),
 T("ok_cap_ht", 1, 0,0,0, 0,0,0, 1, 1, false, MODE_ANAC, 1, "1:Capabilities.HTCapabilities=Wg==\n", NULL),
 T("ok_cap_vht", 1, 0,0,0, 0,0,0, 1, 1, false, MODE_ANAC, 1, "1:Capabilities.VHTCapabilities=//r/+iZg\n", NULL),
 T("ok_cap_radio3", 3, 0,0,0, 0,0,0, 4, 1, false, MODE_ANAC, 3, "3:X_AIRTIES_OperatingStandards=a,n,ac\n", NULL),
 T("ok_cap_absent_empty_ht", 1, 0,0,0, 0,0,0, 0, 1, false, MODE_ANAC, 1, "1:Capabilities.HTCapabilities=\n", "X_AIRTIES_OperatingStandards"),
 T("ok_cap_absent_empty_vht", 1, 0,0,0, 0,0,0, 0, 1, false, MODE_ANAC, 1, "1:Capabilities.VHTCapabilities=\n", NULL),
 /* ---- sub-table paths ---- */
 T("ok_path_curops", 1, 0,0,0, 0,0,0, 0, 1, false, 0, 1, "0:curops_path=" R "1.CurrentOperatingClassProfile.\n", NULL),
 T("ok_path_capops", 1, 0,0,0, 0,0,0, 0, 1, false, 0, 1, "0:capops_path=" R "1.Capabilities.CapableOperatingClassProfile.\n", NULL),
 T("ok_path_wf6ap", 1, 0,0,0, 0,0,0, 0, 1, false, 0, 1, "1:wf6ap_path=" R "1.Capabilities.WiFi6APRole.\n", NULL),
 T("ok_path_wf7ap", 1, 0,0,0, 0,0,0, 0, 1, false, 0, 1, "1:wf7ap_path=" R "1.Capabilities.WiFi7APRole.\n", NULL),
 T("ok_path_bss_radio2", 2, 0,0,0, 0,0,0, 0, 1, false, 0, 2, "0:bss_path=" R "2.BSS.\n", NULL),
 {"ok_long_root_truncated", "LONG", 1, -1, {0,0,0}, {0,0,0}, 0, 1, false, 0, 1, NULL, NULL, false},
 /* ---- num_radios above 3 but every radio has a cap entry: found before the loop leaves the array ---- */
 T("ok_numradios_4_all_cap", 3, 0,0,0, 0,0,0, 7, 1, false, MODE_ANAC, 3, NULL, NULL),
 /* ---- CRASH cases (run last, unforked) ---- */
 {"crash_opclass_count_65", R, 1, 65, {64,0,0}, {0,0,0}, 1, 1, false, 0, -1, NULL, NULL, true},
 {"crash_opclass_count_255", R, 1, 255, {64,0,0}, {0,0,0}, 1, 1, false, 0, -1, NULL, NULL, true},
 {"crash_numradios_4_no_cap", R, 4, -1, {0,0,0}, {0,0,0}, 0, 1, false, 0, -1, NULL, NULL, true},
 {"crash_numradios_100_no_cap", R, 100, -1, {0,0,0}, {0,0,0}, 0, 1, false, 0, -1, NULL, NULL, true},

 { NULL, NULL, 0, 0, {0,0,0}, {0,0,0}, 0, 0, false, 0, 0, NULL, NULL, false }  /* sentinel */
};

void construct_input(const test_case_t *tc)
{
    memset(root_store, 0, sizeof(root_store));
    if (!strcmp(tc->root, "LONG")) { memset(root_store + RTP_LEFT, 'a', 600); }
    else snprintf(root_store + RTP_LEFT, RTP_ROOT_SZ, "%s", tc->root);
    root_ptr = root_store + RTP_LEFT;
    g_rec[0] = '\0'; g_ids = 0;
    dm_easy_mesh_t *dm = new dm_easy_mesh_t;
    memset((void *)dm, 0, sizeof(*dm));
    dm->m_num_radios = tc->n_radios;
    for (int r = 0; r < EM_MAX_BANDS; r++) {
        em_radio_info_t *ri = &dm->m_radio[r].info;
        unsigned char m[6] = {2, 0, 0, 0, 0, (unsigned char)(r + 1)};
        memcpy(ri->id.ruid, m, 6);
        ri->enabled = true; ri->number_of_bss = tc->nbss; ri->noise = 90; ri->utilization = 12;
        ri->transmit = 3; ri->receive_self = 4; ri->receive_other = 5; ri->radio_temp = 55;
        snprintf(ri->chip_vendor, sizeof(ri->chip_vendor), "Vend");
        if (tc->has_cap & (1 << r)) {
            em_radio_cap_info_t *ci = &dm->m_radio_cap[r].m_radio_cap_info;
            memcpy(ci->ruid.mac, m, 6);
            ci->mode = tc->mode;
            ci->ht_cap.max_sprt_tx_streams = 2; ci->ht_cap.max_sprt_rx_streams = 2;
            ci->ht_cap.gi_sprt_20mhz = true; ci->ht_cap.ht_sprt_40mhz = true;
            ci->vht_cap.sprt_tx_mcs = 0xfffa; ci->vht_cap.sprt_rx_mcs = 0xfffa;
            ci->vht_cap.max_sprt_tx_streams = 2; ci->vht_cap.max_sprt_rx_streams = 2;
            ci->vht_cap.gi_sprt_80mhz = true; ci->vht_cap.sprt_160mhz = true; ci->vht_cap.su_beamformer_cap = true;
        }
    }
    unsigned int n = 0;
    for (int r = 0; r < 3; r++) {
        for (int k = 0; k < 2; k++) {
            int cnt = k == 0 ? tc->cur[r] : tc->cap[r];
            for (int i = 0; i < cnt && n < EM_MAX_OPCLASS; i++, n++) {
                em_op_class_info_t *oc = &dm->m_op_class[n].info;
                unsigned char m[6] = {2, 0, 0, 0, 0, (unsigned char)(r + 1)};
                memcpy(oc->id.ruid, m, 6);
                oc->id.type = k == 0 ? em_op_class_type_current : em_op_class_type_capability;
                oc->op_class = 100 + n;
            }
        }
    }
    dm->m_num_opclass = tc->n_oc >= 0 ? (unsigned int)tc->n_oc : n;
    g_dm = dm;
    set_bh(tc->bh);
}

void teardown(void)
{
    delete g_dm; g_dm = NULL;
}

} /* namespace rtp */
