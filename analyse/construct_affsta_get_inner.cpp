/*
 * TEST CASES / CONSTRUCTOR: construct_affsta_get_inner
 *
 * event_name lives in name_store at offset AFG_LEFT (runner poisons the bytes in front of it and past its
 * NUL). One device 1 (or the MAC alias 02:00:00:00:00:01) with 2 AP MLDs (MAC 02:00:00:00:a0:01 / a0:02, selected by
 * number or alias), 3 STA MLDs (MAC 02:00:00:00:b0:0n, selected by MAC alias because get_dm_sta_mld() is wrong for a
 * numeric instance) and these affiliated STAs:
 *   STA MLD b0:01 (2 entries): [0] BSSID 02:00:00:00:10:01 link 02:00:00:01:00:01   [1] BSSID 02:00:00:00:10:02 link 02:00:00:01:00:02
 *   STA MLD b0:02 (1 entry):   [0] BSSID 02:00:00:00:20:01 link 02:00:00:01:00:03        STA MLD b0:03: no entries
 * and a STA map with 3 associated STAs (id 02:00:00:01:00:n, bytes_tx 1000n+1, bytes_rx 1000n+2, packets 1000n+3 / +4, errors
 * 1000n+5, rcpi 10n, est dl / ul 1000n+6 / +7). The handler picks the first associated STA whose id is DIFFERENT from the
 * link address (memcmp(...) != 0, inverted), so the statistics parameters report another STA than the affiliated one:
 * the [spec] cases expect the STA with the matching id and fail.
 *
 * expect_rc: 0 success, 2 invalid_input, 5 destination_not_found, 25 invalid_namespace. variant: 0 normal, 1 STA MLD 1
 * num_affiliated_sta = 100 (> 64 entries of affiliated_sta[]), 2 empty STA map. Cases marked [spec] are wrong behaviour.
 * Cases named crash_* ABORT on the original handler: they run last and UNFORKED so a plain `make` stops with the ASan
 * report; FORK_CRASH=1 forks each one.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "affsta_get_inner.h"

namespace afg {

alignas(16) char name_store[AFG_LEFT + AFG_NAME_SZ + AFG_PAD];

#define N "Device.WiFi.DataElements.Network."
#define M1 "[02:00:00:00:b0:01]"
#define M2 "[02:00:00:00:b0:02]"
#define EV(ap, sm, aff, p) N "Device.1.APMLD." ap ".STAMLD." sm ".AffiliatedSTA." aff "." p
/* {name, event, no_pdata, expect_rc, expect_val, variant, crash} */
#define OKV(n, aff, p, v) {n, EV("1", M1, aff, p), false, 0, v, 0, false}
#define RJ(n, ev, rc) {n, ev, false, rc, NULL, 0, false}
#define CR(n, ev) {n, ev, false, 2, NULL, 0, true}

test_case_t suite[] = {
 /* ---- address parameters ---- */
 OKV("ok_mac_aff1", "1", "MACAddress", "02:00:00:01:00:01"),
 OKV("ok_bssid_aff1", "1", "BSSID", "02:00:00:00:10:01"),
 OKV("ok_mac_aff2", "2", "MACAddress", "02:00:00:01:00:02"),
 OKV("ok_bssid_aff2", "2", "BSSID", "02:00:00:00:10:02"),
 {"ok_stamld2_mac", EV("1", M2, "1", "MACAddress"), false, 0, "02:00:00:01:00:03", 0, false},
 {"ok_stamld2_bssid", EV("1", M2, "1", "BSSID"), false, 0, "02:00:00:00:20:01", 0, false},
 {"ok_apmld2_alias_path", EV("[02:00:00:00:a0:02]", M1, "1", "MACAddress"), false, 0, "02:00:00:01:00:01", 0, false},
 {"ok_device_alias", N "Device.[02:00:00:00:00:01].APMLD.1.STAMLD." M1 ".AffiliatedSTA.2.BSSID", false, 0, "02:00:00:00:10:02", 0, false},
 /* ---- statistics with no STA in the map: reported as 0 ---- */
 {"ok_bytes_sent_no_sta", EV("1", M1, "1", "BytesSent"), false, 0, "0", 2, false},
 {"ok_signal_no_sta", EV("1", M1, "1", "SignalStrength"), false, 0, "0", 2, false},
 {"ok_est_dl_no_sta", EV("1", M1, "2", "EstMACDataRateDownlink"), false, 0, "0", 2, false},
 /* ---- rejected ---- */
 RJ("rej_invalid_param", EV("1", M1, "1", "Foo"), 5),
 RJ("rej_no_dot_in_name", "MACAddress", 2),
 {"rej_pdata_null", EV("1", M1, "1", "MACAddress"), true, 2, NULL, 0, false},
 {"rej_event_null", NULL, false, 2, NULL, 0, false},
 RJ("rej_device_not_found", N "Device.9.APMLD.1.STAMLD." M1 ".AffiliatedSTA.1.MACAddress", 25),
 RJ("rej_apmld_9", EV("9", M1, "1", "MACAddress"), 25),
 RJ("rej_apmld_0", EV("0", M1, "1", "MACAddress"), 25),
 RJ("rej_stamld_alias_not_found", EV("1", "[02:00:00:00:b0:99]", "1", "MACAddress"), 25),
 RJ("rej_aff_0", EV("1", M1, "0", "MACAddress"), 25),
 RJ("rej_aff_3_of_2", EV("1", M1, "3", "MACAddress"), 25),
 RJ("rej_aff_negative", EV("1", M1, "-1", "MACAddress"), 25),
 RJ("rej_aff_alias", EV("1", M1, "[02:00:00:01:00:01]", "MACAddress"), 25),
 RJ("rej_stamld2_aff_2_of_1", EV("1", M2, "2", "MACAddress"), 25),
 RJ("rej_stamld3_without_entries", EV("1", "[02:00:00:00:b0:03]", "1", "MACAddress"), 25),
 /* ---- [spec]: wrong behaviour, no abort ---- */
 {"rej_aff_trailing_text [spec]", EV("1", M1, "1x", "MACAddress"), false, 25, NULL, 0, false},
 {"spec_bytes_sent_of_matching_sta [spec]", EV("1", M1, "1", "BytesSent"), false, 0, "1001", 0, false},
 {"spec_bytes_received_of_matching_sta [spec]", EV("1", M1, "2", "BytesReceived"), false, 0, "2002", 0, false},
 {"spec_packets_received_of_matching_sta [spec]", EV("1", M1, "1", "PacketsReceived"), false, 0, "1004", 0, false},
 {"spec_signal_of_matching_sta [spec]", EV("1", M1, "1", "SignalStrength"), false, 0, "10", 0, false},
 {"spec_est_ul_of_matching_sta [spec]", EV("1", M1, "2", "EstMACDataRateUplink"), false, 0, "2007", 0, false},
 /* ---- CRASH cases on the original handler: run last, unforked ---- */
 CR("crash_method_name_short", "X.MACAddress"),
 CR("crash_path_without_device", N "MACAddress"),
 CR("crash_path_without_apmld", N "Device.1.MACAddress"),
 CR("crash_path_without_stamld", N "Device.1.APMLD.1.MACAddress"),
 CR("crash_path_without_affsta", N "Device.1.APMLD.1.STAMLD." M1 ".MACAddress"),
 {"crash_num_affiliated_sta_100_aff_65", EV("1", M1, "65", "MACAddress"), false, 0, NULL, 1, true},
 {"crash_num_affiliated_sta_100_aff_70", EV("1", M1, "70", "BSSID"), false, 0, NULL, 1, true},
 { NULL, NULL, false, 0, NULL, 0, false }  /* sentinel */
};

static dm_sta_t *g_sta[AFG_MAXSTA];
static sta_map_t g_map;

void construct_input(const test_case_t *tc)
{
    memset(name_store, 0, sizeof(name_store));
    if (tc->event) snprintf(name_store + AFG_LEFT, AFG_NAME_SZ, "%s", tc->event);
    g_nset = 0; g_val[0] = '\0';

    g_dm = new dm_easy_mesh_t;
    memset((void *)g_dm, 0, sizeof(*g_dm));
    g_dm->m_num_ap_mld = 2;
    for (int a = 0; a < 2; a++) { unsigned char m[6] = {2, 0, 0, 0, 0xa0, (unsigned char)(a + 1)}; memcpy(g_dm->m_ap_mld[a].info.mac_addr, m, 6); }
    g_dm->m_num_assoc_sta_mld = 3;
    for (int s = 0; s < 3; s++) {
        em_assoc_sta_mld_info_t *smi = &g_dm->m_assoc_sta_mld[s].info;
        unsigned char m[6] = {2, 0, 0, 0, 0xb0, (unsigned char)(s + 1)}, ap[6] = {2, 0, 0, 0, 0xa0, (unsigned char)(s == 2 ? 2 : 1)};
        memcpy(smi->mac_addr, m, 6); memcpy(smi->ap_mld_mac_addr, ap, 6);
    }
    em_assoc_sta_mld_info_t *s1 = &g_dm->m_assoc_sta_mld[0].info, *s2 = &g_dm->m_assoc_sta_mld[1].info;
    s1->num_affiliated_sta = 2;
    { unsigned char b0[6] = {2,0,0,0,0x10,0x01}, l0[6] = {2,0,0,1,0,1}, b1[6] = {2,0,0,0,0x10,0x02}, l1[6] = {2,0,0,1,0,2};
      memcpy(s1->affiliated_sta[0].bssid, b0, 6); memcpy(s1->affiliated_sta[0].link_addr, l0, 6);
      memcpy(s1->affiliated_sta[1].bssid, b1, 6); memcpy(s1->affiliated_sta[1].link_addr, l1, 6); }
    s2->num_affiliated_sta = 1;
    { unsigned char b0[6] = {2,0,0,0,0x20,0x01}, l0[6] = {2,0,0,1,0,3};
      memcpy(s2->affiliated_sta[0].bssid, b0, 6); memcpy(s2->affiliated_sta[0].link_addr, l0, 6); }
    if (tc->variant == 1) s1->num_affiliated_sta = 100;

    memset(&g_map, 0, sizeof(g_map));
    for (int i = 0; i < AFG_MAXSTA; i++) g_sta[i] = NULL;
    if (tc->variant != 2) {
        for (int i = 0; i < 3; i++) {
            dm_sta_t *st = new dm_sta_t;
            memset((void *)st, 0, sizeof(*st));
            em_sta_info_t *si = &st->info;
            unsigned char id[6] = {2, 0, 0, 1, 0, (unsigned char)(i + 1)};
            memcpy(si->id, id, 6);
            unsigned int k = (unsigned int)(i + 1);
            si->associated = true;
            si->bytes_tx = 1000 * k + 1; si->bytes_rx = 1000 * k + 2; si->pkts_tx = 1000 * k + 3; si->pkts_rx = 1000 * k + 4;
            si->errors_tx = 1000 * k + 5; si->rcpi = (int)(10 * k); si->est_dl_rate = 1000 * k + 6; si->est_ul_rate = 1000 * k + 7;
            g_sta[i] = st; g_map.p[g_map.n++] = st;
        }
    }
    g_dm->m_sta_map = &g_map;
}

void teardown(void)
{
    for (int i = 0; i < AFG_MAXSTA; i++) { delete g_sta[i]; g_sta[i] = NULL; }
    delete g_dm; g_dm = NULL;
}

} /* namespace afg */
