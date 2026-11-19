/*
 * TEST CASES / CONSTRUCTOR: construct_rcaps_get_inner
 *
 * event_name lives in name_store at offset RCG_LEFT (runner poisons the bytes in front of it and past its
 * NUL). One device 1 (or the MAC alias 02:00:00:00:00:01) with radios r = 1..3, RUID 02:00:00:00:00:r, and
 * radio caps for radios 1 and 2 only (radio 3 has none):
 *   radio 1: HT tx 2 / rx 3 streams, GI20, HT40       -> "ag=="   VHT mcs fffa/fffa, tx 2 / rx 3, GI80, 160, SU -> "//r/+ipg"   modes a,n,ac
 *   radio 2: HT tx 0 / rx 0, GI40                     -> "BA=="   VHT mcs aaaa/5555, tx 4 / rx 4, GI160, 80+80, MU -> "qqpVVW2Q"  modes b,g,n,ax,be
 * (base64 strings computed independently, by python, from the TR-181 octet layout the functions document) and
 * this op class list (m_num_opclass = 6):
 *   [0] radio 1 current  [1] radio 1 capability  [2] radio 1 capability
 *   [3] radio 2 capability  [4] radio 3 capability  [5] (empty entry, type none)
 * so CapableOperatingClassProfileNumberOfEntries is 2 / 1 / 1 for radio 1 / 2 / 3.
 *
 * expect_rc: 0 success, 2 invalid_input, 25 invalid_namespace. Cases marked [spec] are wrong behaviour (an
 * instance like "1abc" is read as 1 by atoi). Cases named crash_* ABORT on the original handler (they run
 * last and UNFORKED so a plain make stops with the ASan report; FORK_CRASH=1 forks each one): method name
 * shorter than the Network prefix, path that stops before the Device / Radio instance (get_table_instance
 * on a name without '.'), Radio instance 0 / 4 / alias / -1 / 1000000 (dm->m_radio[radio_instance - 1]) and
 * m_num_opclass 100 (loop runs past m_op_class[64]).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rcaps_get_inner.h"

namespace rcg {

alignas(16) char name_store[RCG_LEFT + RCG_NAME_SZ + RCG_PAD];

#define N "Device.WiFi.DataElements.Network."
#define EV(rad, p) N "Device.1.Radio." rad "." p
/* {name, event, no_pdata, no_dm, expect_rc, expect_val, variant, crash} */
#define OKV(n, rad, p, v) {n, EV(rad, p), false, false, 0, v, 0, false}
#define RJ(n, ev) {n, ev, false, false, 2, NULL, 0, false}
#define CR(n, ev) {n, ev, false, false, 2, NULL, 0, true}

test_case_t suite[] = {
 /* ---- every parameter name ---- */
 OKV("ok_ht_radio1", "1", "HTCapabilities", "ag=="),
 OKV("ok_ht_radio2", "2", "HTCapabilities", "BA=="),
 OKV("ok_vht_radio1", "1", "VHTCapabilities", "//r/+ipg"),
 OKV("ok_vht_radio2", "2", "VHTCapabilities", "qqpVVW2Q"),
 OKV("ok_standards_radio1", "1", "X_AIRTIES_OperatingStandards", "a,n,ac"),
 OKV("ok_standards_radio2", "2", "X_AIRTIES_OperatingStandards", "b,g,n,ax,be"),
 /* ---- capable operating class count (current / empty entries are skipped, no radio cap needed) ---- */
 OKV("ok_capop_count_radio1", "1", "CapableOperatingClassProfileNumberOfEntries", "2"),
 OKV("ok_capop_count_radio2", "2", "CapableOperatingClassProfileNumberOfEntries", "1"),
 OKV("ok_capop_count_radio3_no_cap", "3", "CapableOperatingClassProfileNumberOfEntries", "1"),
 /* ---- device selected by MAC alias ---- */
 {"ok_alias_path", N "Device.[02:00:00:00:00:01].Radio.2.HTCapabilities", false, false, 0, "BA==", 0, false},
 {"ok_alias_path_vht", N "Device.[02:00:00:00:00:01].Radio.1.VHTCapabilities", false, false, 0, "//r/+ipg", 0, false},
 /* ---- rejected ---- */
 RJ("rej_invalid_param", EV("1", "Foo")),
 RJ("rej_param_lowercase", EV("1", "htcapabilities")),
 RJ("rej_radio3_without_radio_cap_ht", EV("3", "HTCapabilities")),
 RJ("rej_radio3_without_radio_cap_vht", EV("3", "VHTCapabilities")),
 RJ("rej_radio3_without_radio_cap_standards", EV("3", "X_AIRTIES_OperatingStandards")),
 {"rej_device_not_found", N "Device.9.Radio.1.HTCapabilities", false, false, 25, NULL, 0, false},
 {"rej_device_alias_not_found", N "Device.[aa:bb:cc:dd:ee:ff].Radio.1.HTCapabilities", false, false, 25, NULL, 0, false},
 {"rej_no_dm", EV("1", "HTCapabilities"), false, true, 25, NULL, 0, false},
 {"rej_event_null", NULL, false, false, 2, NULL, 0, false},
 {"rej_pdata_null", EV("1", "HTCapabilities"), true, false, 2, NULL, 0, false},
 RJ("rej_no_dot", "HTCapabilities"),
 /* ---- [spec]: wrong behaviour, no abort (atoi reads the leading digits) ---- */
 {"rej_radio_1abc [spec]", EV("1abc", "HTCapabilities"), false, false, 2, NULL, 0, false},
 {"rej_radio_2x [spec]", EV("2x", "HTCapabilities"), false, false, 2, NULL, 0, false},
 /* ---- CRASH cases on the original handler (rejected / clamped after the fix) ---- */
 CR("crash_method_short", "X.HTCapabilities"),
 CR("crash_path_without_device", N "HTCapabilities"),
 CR("crash_path_without_radio", N "Device.1.HTCapabilities"),
 CR("crash_radio_0", EV("0", "HTCapabilities")),
 CR("crash_radio_4", EV("4", "HTCapabilities")),
 CR("crash_radio_alias", EV("[x]", "HTCapabilities")),
 CR("crash_radio_negative", EV("-1", "HTCapabilities")),
 CR("crash_radio_huge", EV("1000000", "HTCapabilities")),
 {"crash_num_opclass_over_max", EV("1", "CapableOperatingClassProfileNumberOfEntries"), false, false, 0, "2", 2, true},

 { NULL, NULL, false, false, 0, NULL, 0, false }  /* sentinel */
};

void construct_input(const test_case_t *tc)
{
    memset(name_store, 0, sizeof(name_store));
    if (tc->event) snprintf(name_store + RCG_LEFT, RCG_NAME_SZ, "%s", tc->event);
    g_nset = 0; g_val[0] = '\0'; g_dm = NULL;
    if (tc->no_dm) return;
    dm_easy_mesh_t *dm = new dm_easy_mesh_t;
    memset((void *)dm, 0, sizeof(*dm));
    for (int r = 1; r <= EM_MAX_BANDS; r++) {
        unsigned char m[6] = {2, 0, 0, 0, 0, (unsigned char)r};
        memcpy(dm->m_radio[r - 1].info.id.ruid, m, 6);
    }
    dm->m_num_radios = 2;
    for (int r = 1; r <= 2; r++) {
        em_radio_cap_info_t *ci = &dm->m_radio_cap[r - 1].m_radio_cap_info;
        unsigned char m[6] = {2, 0, 0, 0, 0, (unsigned char)r};
        memcpy(ci->ruid.mac, m, 6);
    }
    em_radio_cap_info_t *c1 = &dm->m_radio_cap[0].m_radio_cap_info, *c2 = &dm->m_radio_cap[1].m_radio_cap_info;
    c1->ht_cap.max_sprt_tx_streams = 2; c1->ht_cap.max_sprt_rx_streams = 3; c1->ht_cap.gi_sprt_20mhz = 1; c1->ht_cap.ht_sprt_40mhz = 1;
    c1->vht_cap.sprt_tx_mcs = 0xfffa; c1->vht_cap.sprt_rx_mcs = 0xfffa; c1->vht_cap.max_sprt_tx_streams = 2; c1->vht_cap.max_sprt_rx_streams = 3;
    c1->vht_cap.gi_sprt_80mhz = 1; c1->vht_cap.sprt_160mhz = 1; c1->vht_cap.su_beamformer_cap = 1;
    c1->mode = (wifi_ieee80211Variant_t)(WIFI_80211_VARIANT_A | WIFI_80211_VARIANT_N | WIFI_80211_VARIANT_AC);
    c2->ht_cap.gi_sprt_40mhz = 1;
    c2->vht_cap.sprt_tx_mcs = 0xaaaa; c2->vht_cap.sprt_rx_mcs = 0x5555; c2->vht_cap.max_sprt_tx_streams = 4; c2->vht_cap.max_sprt_rx_streams = 4;
    c2->vht_cap.gi_sprt_160mhz = 1; c2->vht_cap.sprt_80_80_mhz = 1; c2->vht_cap.mu_beamformer_cap = 1;
    c2->mode = (wifi_ieee80211Variant_t)(WIFI_80211_VARIANT_B | WIFI_80211_VARIANT_G | WIFI_80211_VARIANT_N | WIFI_80211_VARIANT_AX | WIFI_80211_VARIANT_BE);
    static const struct { unsigned char radio; int type; } ocs[] = {
        {1, 1}, {1, 2}, {1, 2}, {2, 2}, {3, 2}, {0, 0},
    };
    for (unsigned int i = 0; i < sizeof(ocs) / sizeof(ocs[0]); i++) {
        dm_op_class_t *oc = &dm->m_op_class[i];
        unsigned char m[6] = {2, 0, 0, 0, 0, ocs[i].radio};
        memcpy(oc->info.id.ruid, m, 6);
        oc->info.id.type = (em_op_class_type_t)ocs[i].type;
    }
    dm->m_num_opclass = (tc->variant == 2) ? 100 : (unsigned int)(sizeof(ocs) / sizeof(ocs[0]));
    g_dm = dm;
}

void teardown(void)
{
    delete g_dm; g_dm = NULL;
}

} /* namespace rcg */
