/*
 * TEST CASES / CONSTRUCTOR: construct_bss_get_inner
 *
 * event_name lives in name_store at offset BGI_LEFT (runner poisons the bytes in front of it and past its
 * NUL). One device 1 (or the MAC alias 02:00:00:00:00:01) with radios r = 1..3, RUID 02:00:00:00:00:r, and
 * this BSS list (m_num_bss = 5):
 *   [0] radio 1 fronthaul BSSID 02:00:00:00:10:01 "ssid1"  [1] radio 1 BSSID 00:..:00 (unused, skipped)
 *   [2] radio 1 backhaul BSSID 02:00:00:00:10:02 "ssid2"   [3] radio 2 fronthaul 02:00:00:00:20:01 "ssid3"
 *   [4] radio 3 fronthaul 02:00:00:00:30:01 "ssid4"
 * so BSS.1 / BSS.2 of radio 1 are entries 0 / 2, BSS.1 of radio 2 is entry 3. Numbers of BSS 1: enabled, last change 11,
 * timestamp "ts1", unicast bytes 101 / 102, multicast 103 / 104, broadcast 105 / 106, est svc params be/bk/vi/vo "be1".."vo1",
 * byte counter units 2, profile 1b allowed 1 / 2b 0, assoc allowed status 3, R1 disallowed 1, R2 0, multi BSSID 1,
 * transmitted BSSID 0, STA count 7.
 *
 * expect_rc: 0 success, 2 invalid_input, 25 invalid_namespace. variant: 0 normal, 1 m_num_bss = 100 (> 24 entries of
 * m_bss[]). Cases marked [spec] are wrong behaviour (an instance like "1x" is read as 1 by atoi). Cases named rej_* / clamp_* in
 * the last block (short method name, path without Device / Radio / BSS, Radio instance 0 / 4 / -1 / 1000000 / alias, m_num_bss 100)
 * ABORTED on the original handler (now fixed by fixes 1-4): the first 9 are rejected (rc 2), m_num_bss is clamped to 24.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bss_get_inner.h"

namespace bgi {

alignas(16) char name_store[BGI_LEFT + BGI_NAME_SZ + BGI_PAD];

#define N "Device.WiFi.DataElements.Network."
#define EV(rad, bss, p) N "Device.1.Radio." rad ".BSS." bss "." p
/* {name, event, no_pdata, expect_rc, expect_val, variant, crash} */
#define OKV(n, p, v) {n, EV("1", "1", p), false, 0, v, 0, false}
#define RJ(n, ev) {n, ev, false, 2, NULL, 0, false}
#define NS(n, ev) {n, ev, false, 25, NULL, 0, false}
#define CR(n, ev) {n, ev, false, 2, NULL, 0, false}

test_case_t suite[] = {
 /* ---- every parameter name (radio 1, BSS 1) ---- */
 OKV("ok_BSSID", "BSSID", "02:00:00:00:10:01"),
 OKV("ok_SSID", "SSID", "ssid1"),
 OKV("ok_Enabled", "Enabled", "1"),
 OKV("ok_LastChange", "LastChange", "11"),
 OKV("ok_TimeStamp", "TimeStamp", "ts1"),
 OKV("ok_UnicastBytesSent", "UnicastBytesSent", "101"),
 OKV("ok_UnicastBytesReceived", "UnicastBytesReceived", "102"),
 OKV("ok_MulticastBytesSent", "MulticastBytesSent", "103"),
 OKV("ok_BroadcastBytesReceived", "BroadcastBytesReceived", "106"),
 OKV("ok_EstServiceParametersBE", "EstServiceParametersBE", "be1"),
 OKV("ok_EstServiceParametersVO", "EstServiceParametersVO", "vo1"),
 OKV("ok_ByteCounterUnits", "ByteCounterUnits", "2"),
 OKV("ok_Profile1bSTAsDisallowed", "Profile1bSTAsDisallowed", "1"),
 OKV("ok_Profile2bSTAsDisallowed", "Profile2bSTAsDisallowed", "0"),
 OKV("ok_AssociationAllowanceStatus", "AssociationAllowanceStatus", "3"),
 OKV("ok_BackhaulUse", "BackhaulUse", "0"),
 OKV("ok_FronthaulUse", "FronthaulUse", "1"),
 OKV("ok_R1disallowed", "R1disallowed", "1"),
 OKV("ok_R2disallowed", "R2disallowed", "0"),
 OKV("ok_MultiBSSID", "MultiBSSID", "1"),
 OKV("ok_TransmittedBSSID", "TransmittedBSSID", "0"),
 OKV("ok_FronthaulAKMsAllowed", "FronthaulAKMsAllowed", "psk,sae"),
 OKV("ok_BackhaulAKMsAllowed_fronthaul_bss", "BackhaulAKMsAllowed", ""),
 OKV("ok_STANumberOfEntries", "STANumberOfEntries", "7"),
 OKV("ok_FronthaulSuiteSelector", "FronthaulSuiteSelector", "0"),
 OKV("ok_BackhaulSuiteSelector", "BackhaulSuiteSelector", "0"),
 /* ---- navigation: the BSS with a zero BSSID is skipped, the backhaul BSS is BSS.2 of radio 1 ---- */
 {"ok_bss2_is_entry2", EV("1", "2", "SSID"), false, 0, "ssid2", 0, false},
 {"ok_bss2_backhaul_akms", EV("1", "2", "BackhaulAKMsAllowed"), false, 0, "wpa2,sae-b", 0, false},
 {"ok_radio2_bss1", EV("2", "1", "SSID"), false, 0, "ssid3", 0, false},
 {"ok_radio3_bss1", EV("3", "1", "SSID"), false, 0, "ssid4", 0, false},
 {"ok_alias_device", N "Device.[02:00:00:00:00:01].Radio.2.BSS.1.SSID", false, 0, "ssid3", 0, false},
 /* ---- rejected ---- */
 RJ("rej_invalid_param", EV("1", "1", "Foo")),
 RJ("rej_no_dot_in_name", "BSSID"),
 {"rej_pdata_null", EV("1", "1", "SSID"), true, 2, NULL, 0, false},
 {"rej_event_null", NULL, false, 2, NULL, 0, false},
 NS("rej_device_not_found", N "Device.9.Radio.1.BSS.1.SSID"),
 NS("rej_bss_0", EV("1", "0", "SSID")),
 NS("rej_bss_9", EV("1", "9", "SSID")),
 NS("rej_radio3_bss2_not_present", EV("3", "2", "SSID")),
 /* ---- [spec]: wrong behaviour (atoi accepts trailing text), no abort ---- */
 {"rej_bss_trailing_text [spec]", EV("1", "1x", "SSID"), false, 2, NULL, 0, false},
 /* ---- were CRASH cases on the original handler (now rejected / clamped) ---- */
 CR("rej_method_name_short", "X.SSID"),
 CR("rej_path_without_device", N "SSID"),
 CR("rej_path_without_radio", N "Device.1.SSID"),
 CR("rej_path_without_bss", N "Device.1.Radio.1.SSID"),
 CR("rej_radio_0", EV("0", "1", "SSID")),
 CR("rej_radio_4", EV("4", "1", "SSID")),
 CR("rej_radio_negative", EV("-1", "1", "SSID")),
 CR("rej_radio_1000000", EV("1000000", "1", "SSID")),
 CR("rej_radio_alias", EV("[02:00:00:00:00:01]", "1", "SSID")),
 {"clamp_num_bss_100", EV("1", "9", "SSID"), false, 25, NULL, 1, false},
 { NULL, NULL, false, 0, NULL, 0, false }  /* sentinel */
};

void construct_input(const test_case_t *tc)
{
    memset(name_store, 0, sizeof(name_store));
    if (tc->event) snprintf(name_store + BGI_LEFT, BGI_NAME_SZ, "%s", tc->event);
    g_nset = 0; g_val[0] = '\0';

    g_dm = new dm_easy_mesh_t;
    memset((void *)g_dm, 0, sizeof(*g_dm));
    for (int r = 0; r < EM_MAX_BANDS; r++) {
        unsigned char ruid[6] = {2, 0, 0, 0, 0, (unsigned char)(r + 1)};
        memcpy(g_dm->m_radio[r].info.id.ruid, ruid, 6);
    }
    int radio[5] = {1, 1, 1, 2, 3};
    unsigned char bssids[5][6] = { {2,0,0,0,0x10,0x01}, {0,0,0,0,0,0}, {2,0,0,0,0x10,0x02}, {2,0,0,0,0x20,0x01}, {2,0,0,0,0x30,0x01} };
    const char *ssids[5] = {"ssid1", "", "ssid2", "ssid3", "ssid4"};
    for (int i = 0; i < 5; i++) {
        em_bss_info_t *bi = &g_dm->m_bss[i].info;
        unsigned char ruid[6] = {2, 0, 0, 0, 0, (unsigned char)radio[i]};
        memcpy(bi->ruid.mac, ruid, 6);
        memcpy(bi->bssid.mac, bssids[i], 6);
        snprintf(bi->ssid, sizeof(bi->ssid), "%s", ssids[i]);
        bi->id.haul_type = (i == 2) ? em_haul_type_backhaul : em_haul_type_fronthaul;
        bi->enabled = true; bi->last_change = 11; snprintf(bi->timestamp, sizeof(bi->timestamp), "ts%d", i + 1);
        bi->numberofsta = 7;
        bi->unicast_bytes_sent = 101; bi->unicast_bytes_rcvd = 102; bi->multicast_bytes_sent = 103;
        bi->multicast_bytes_rcvd = 104; bi->broadcast_bytes_sent = 105; bi->broadcast_bytes_rcvd = 106;
        snprintf(bi->est_svc_params_be, sizeof(bi->est_svc_params_be), "be%d", i + 1);
        snprintf(bi->est_svc_params_bk, sizeof(bi->est_svc_params_bk), "bk%d", i + 1);
        snprintf(bi->est_svc_params_vi, sizeof(bi->est_svc_params_vi), "vi%d", i + 1);
        snprintf(bi->est_svc_params_vo, sizeof(bi->est_svc_params_vo), "vo%d", i + 1);
        bi->byte_counter_units = 2; bi->profile_1b_sta_allowed = true; bi->profile_2b_sta_allowed = false;
        bi->assoc_allowed_status = 3; bi->r1_disallowed = true; bi->r2_disallowed = false;
        bi->multi_bssid = true; bi->transmitted_bssid = false;
    }
    g_dm->m_num_bss = (tc->variant == 1) ? 100 : 5;
}

void teardown(void)
{
    delete g_dm; g_dm = NULL;
}

} /* namespace bgi */
