/*
 * TEST CASES / CONSTRUCTOR: construct_sta_get_inner
 *
 * event_name lives in name_store at offset SGI_LEFT (runner poisons the bytes in front of it and past its
 * NUL). One device 1 (or the MAC alias 02:00:00:00:00:01) with radios r = 1..3, RUID 02:00:00:00:00:r, and
 * this BSS list (m_num_bss = 5):
 *   [0] radio 1 BSSID 02:00:00:00:10:01  [1] radio 1 BSSID 00:..:00 (unused, skipped)  [2] radio 1 BSSID 02:00:00:00:10:02
 *   [3] radio 2 BSSID 02:00:00:00:20:01  [4] radio 3 BSSID 02:00:00:00:30:01
 * so BSS.1 / BSS.2 of radio 1 are entries 0 / 2, BSS.1 of radio 2 is entry 3. STAs (id 02:00:00:01:00:n):
 *   1 BSS 10:01 associated (ts "t1", ht "ab", vht "cd", frame_body bytes 0..7)   2 BSS 10:01 associated
 *   3 BSS 10:01 NOT associated (skipped)   4 BSS 10:02 associated   5 BSS 20:01 associated
 * so STA.1 / STA.2 of radio 1 BSS 1 are STAs 1 / 2, STA.3 does not exist. Numbers of STA 1: dl 111, ul 222, util rx 3,
 * util tx 4, est dl 555, est ul 666, rcpi 77, last connect 888, bytes 1001 / 1002, packets 2001 / 2002, errors 3 / 4, retrans 5.
 *
 * expect_rc: 0 success, 2 invalid_input, 25 invalid_namespace. variant: 0 normal, 1 m_num_bss = 100 (> 24 entries of
 * m_bss[]), 2 / 3 STA 1 frame_body_len = 513 / 65534 (> 512), 4 = 512, 5 = 0. Cases marked [spec] are wrong behaviour
 * (an instance like "1abc" is read as 1 by atoi). Cases named crash_* ABORT on the original handler: they run last and
 * UNFORKED so a plain `make` stops with the ASan report; FORK_CRASH=1 forks each one.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sta_get_inner.h"

namespace sgi {

alignas(16) char name_store[SGI_LEFT + SGI_NAME_SZ + SGI_PAD];

#define N "Device.WiFi.DataElements.Network."
#define EV(rad, bss, sta, p) N "Device.1.Radio." rad ".BSS." bss ".STA." sta "." p
/* {name, event, no_pdata, expect_rc, expect_val, variant, crash} */
#define OKV(n, p, v) {n, EV("1", "1", "1", p), false, 0, v, 0, false}
#define RJ(n, ev) {n, ev, false, 2, NULL, 0, false}
#define NS(n, ev) {n, ev, false, 25, NULL, 0, false}
#define CR(n, ev) {n, ev, false, 2, NULL, 0, true}

test_case_t suite[] = {
 /* ---- every parameter name (radio 1, BSS 1, STA 1) ---- */
 OKV("ok_MACAddress", "MACAddress", "02:00:00:01:00:01"),
 OKV("ok_TimeStamp", "TimeStamp", "t1"),
 OKV("ok_HTCapabilities", "HTCapabilities", "ab"),
 OKV("ok_VHTCapabilities", "VHTCapabilities", "cd"),
 OKV("ok_ClientCapabilities", "ClientCapabilities", "AAECAwQFBgc="),
 OKV("ok_LastDataDownlinkRate", "LastDataDownlinkRate", "111"),
 OKV("ok_LastDataUplinkRate", "LastDataUplinkRate", "222"),
 OKV("ok_UtilizationTransmit", "UtilizationTransmit", "4"),
 OKV("ok_EstMACDataRateDownlink", "EstMACDataRateDownlink", "555"),
 OKV("ok_SignalStrength", "SignalStrength", "77"),
 OKV("ok_LastConnectTime", "LastConnectTime", "888"),
 OKV("ok_BytesSent", "BytesSent", "1001"),
 OKV("ok_PacketsSent", "PacketsSent", "2001"),
 OKV("ok_ErrorsSent", "ErrorsSent", "3"),
 OKV("ok_RetransCount", "RetransCount", "5"),
 OKV("ok_IPV4Address", "IPV4Address", ""),
 OKV("ok_PairwiseAKM", "PairwiseAKM", "0"),
 OKV("ok_wifi6_HE160", "HE160", "1"),
 OKV("ok_wifi6_HE8080", "HE8080", "0"),
 /* ---- navigation: the BSS with a zero BSSID and the not associated STA are skipped ---- */
 {"ok_bss2_is_entry2_sta1", EV("1", "2", "1", "MACAddress"), false, 0, "02:00:00:01:00:04", 0, false},
 {"ok_sta2_of_bss1", EV("1", "1", "2", "MACAddress"), false, 0, "02:00:00:01:00:02", 0, false},
 {"ok_radio2_bss1_sta1", EV("2", "1", "1", "MACAddress"), false, 0, "02:00:00:01:00:05", 0, false},
 {"ok_alias_device", N "Device.[02:00:00:00:00:01].Radio.2.BSS.1.STA.1.MACAddress", false, 0, "02:00:00:01:00:05", 0, false},
 /* ---- frame_body_len at the edge ---- */
 {"ok_frame_body_len_0", EV("1", "1", "1", "ClientCapabilities"), false, 0, "", 5, false},
 {"ok_frame_body_len_512", EV("1", "1", "1", "MACAddress"), false, 0, "02:00:00:01:00:01", 4, false},
 /* ---- rejected ---- */
 RJ("rej_invalid_param", EV("1", "1", "1", "Foo")),
 NS("rej_device_not_found", N "Device.9.Radio.1.BSS.1.STA.1.MACAddress"),
 NS("rej_bss_0", EV("1", "0", "1", "MACAddress")),
 NS("rej_bss_9", EV("1", "9", "1", "MACAddress")),
 RJ("rej_sta_not_associated", EV("1", "1", "3", "MACAddress")),
 RJ("rej_sta_9", EV("1", "1", "9", "MACAddress")),
 RJ("rej_sta_0", EV("1", "1", "0", "MACAddress")),
 RJ("rej_radio3_bss1_without_sta", EV("3", "1", "1", "MACAddress")),
 /* ---- [spec]: wrong behaviour (atoi accepts trailing text), no abort ---- */
 {"rej_bss_trailing_text [spec]", EV("1", "1x", "1", "MACAddress"), false, 2, NULL, 0, false},
 {"rej_sta_trailing_text [spec]", EV("1", "1", "1x", "MACAddress"), false, 2, NULL, 0, false},
 /* ---- CRASH cases on the original handler: run last, unforked ---- */
 {"crash_event_null", NULL, false, 2, NULL, 0, true},
 CR("crash_method_name_short", "X.MACAddress"),
 CR("crash_path_without_device", N "MACAddress"),
 CR("crash_path_without_radio", N "Device.1.MACAddress"),
 CR("crash_path_without_bss", N "Device.1.Radio.1.MACAddress"),
 CR("crash_path_without_sta", N "Device.1.Radio.1.BSS.1.MACAddress"),
 CR("crash_radio_0", EV("0", "1", "1", "MACAddress")),
 CR("crash_radio_4", EV("4", "1", "1", "MACAddress")),
 CR("crash_radio_negative", EV("-1", "1", "1", "MACAddress")),
 CR("crash_radio_1000000", EV("1000000", "1", "1", "MACAddress")),
 CR("crash_radio_alias", EV("[02:00:00:00:00:01]", "1", "1", "MACAddress")),
 {"crash_num_bss_100", EV("1", "9", "1", "MACAddress"), false, 25, NULL, 1, true},
 {"crash_frame_body_len_513", EV("1", "1", "1", "MACAddress"), false, 0, NULL, 2, true},
 {"crash_frame_body_len_513_client_caps", EV("1", "1", "1", "ClientCapabilities"), false, 0, NULL, 2, true},
 {"crash_frame_body_len_65534", EV("1", "1", "1", "MACAddress"), false, 0, NULL, 3, true},
 { NULL, NULL, false, 0, NULL, 0, false }  /* sentinel */
};

static dm_sta_t *g_sta[SGI_MAXSTA];
static sta_map_t g_map;

void construct_input(const test_case_t *tc)
{
    memset(name_store, 0, sizeof(name_store));
    if (tc->event) snprintf(name_store + SGI_LEFT, SGI_NAME_SZ, "%s", tc->event);
    g_nset = 0; g_val[0] = '\0';

    g_dm = new dm_easy_mesh_t;
    memset((void *)g_dm, 0, sizeof(*g_dm));
    for (int r = 0; r < EM_MAX_BANDS; r++) {
        unsigned char ruid[6] = {2, 0, 0, 0, 0, (unsigned char)(r + 1)};
        memcpy(g_dm->m_radio[r].info.id.ruid, ruid, 6);
    }
    struct { int radio; unsigned char b; } bl[5] = { {1, 0x01}, {1, 0}, {1, 0x02}, {2, 0x21}, {3, 0x31} };
    unsigned char bssids[5][6] = { {2,0,0,0,0x10,0x01}, {0,0,0,0,0,0}, {2,0,0,0,0x10,0x02}, {2,0,0,0,0x20,0x01}, {2,0,0,0,0x30,0x01} };
    for (int i = 0; i < 5; i++) {
        unsigned char ruid[6] = {2, 0, 0, 0, 0, (unsigned char)bl[i].radio};
        memcpy(g_dm->m_bss[i].info.ruid.mac, ruid, 6);
        memcpy(g_dm->m_bss[i].info.bssid.mac, bssids[i], 6);
    }
    g_dm->m_num_bss = (tc->variant == 1) ? 100 : 5;

    memset(&g_map, 0, sizeof(g_map));
    struct { unsigned char b0, b1; bool assoc; } sd[5] = { {0x10,0x01,true}, {0x10,0x01,true}, {0x10,0x01,false}, {0x10,0x02,true}, {0x20,0x01,true} };
    for (int i = 0; i < SGI_MAXSTA; i++) g_sta[i] = NULL;
    for (int i = 0; i < 5; i++) {
        dm_sta_t *st = new dm_sta_t;
        memset((void *)st, 0, sizeof(*st));
        em_sta_info_t *si = &st->info;
        unsigned char id[6] = {2, 0, 0, 1, 0, (unsigned char)(i + 1)}, bs[6] = {2, 0, 0, 0, sd[i].b0, sd[i].b1};
        memcpy(si->id, id, 6); memcpy(si->bssid, bs, 6);
        si->associated = sd[i].assoc;
        snprintf(si->timestamp, sizeof(si->timestamp), "t%d", i + 1);
        snprintf(si->ht_cap, sizeof(si->ht_cap), "ab");
        snprintf(si->vht_cap, sizeof(si->vht_cap), "cd");
        si->frame_body_len = 8;
        for (int k = 0; k < EM_MAX_FRAME_BODY_LEN; k++) si->frame_body[k] = (unsigned char)k;
        si->last_dl_rate = 111; si->last_ul_rate = 222; si->util_rx = 3; si->util_tx = 4;
        si->est_dl_rate = 555; si->est_ul_rate = 666; si->rcpi = 77; si->last_conn_time = 888;
        si->bytes_tx = 1001; si->bytes_rx = 1002; si->pkts_tx = 2001; si->pkts_rx = 2002;
        si->errors_tx = 3; si->errors_rx = 4; si->retrans_count = 5;
        g_sta[i] = st; g_map.p[g_map.n++] = st;
    }
    if (tc->variant == 2) g_sta[0]->info.frame_body_len = 513;
    if (tc->variant == 3) g_sta[0]->info.frame_body_len = 65534;
    if (tc->variant == 4) g_sta[0]->info.frame_body_len = 512;
    if (tc->variant == 5) g_sta[0]->info.frame_body_len = 0;
    g_dm->m_sta_map = &g_map;
}

void teardown(void)
{
    for (int i = 0; i < SGI_MAXSTA; i++) { delete g_sta[i]; g_sta[i] = NULL; }
    delete g_dm; g_dm = NULL;
}

} /* namespace sgi */
