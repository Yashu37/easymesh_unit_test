/*
 * TEST CASES / CONSTRUCTOR: construct_bss_tget_params
 *
 * root lives in root_store at offset BTP_ROOT_LEFT (runner poisons the bytes in front of it and past its
 * NUL); root "LONG" is a 600-character prefix. One data model whose BSS table holds the entries of the case
 * (S(radio, zero_bssid, haul, enabled, nsta): BSSID 02:00:00:<radio>:00:<n>, RUID 02:00:00:00:00:<radio>,
 * SSID "SSID<n>", n = position + 1, byte_counter_units 2); ri is radio ri_radio. fill_all=N instead fills N
 * valid radio-1 entries (limit cases). The recorded lines are "idx:name=value"; idx numbers only the BSSs that
 * are listed (non-zero BSSID, same radio), 1-based.
 *
 * Expected: always bus_error_success. The last 3 cases (raw m_num_bss above the 24-entry m_bss[]) ABORTED on
 * the original handler (get_num_bss() is not clamped, get_bss(i) = &m_bss[i]); with fix 1 the count is clamped
 * to EM_MAX_BSSS and they pass as clamp_*.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bss_tget_params.h"

namespace btp {

alignas(16) char root_store[BTP_ROOT_LEFT + BTP_ROOT_SZ + 64];

#define R "Device.WiFi.DataElements.Network.Device.1.Radio.1.BSS."
#define S(r, z, h, e, n) {r, z, h, e, n}
#define E0 S(0, false, 0, false, 0)
#define ONE1 {S(1, false, 0, true, 3), E0, E0, E0, E0, E0}
/* {name, root, ri_radio, {bss specs}, fill_all, n_bss, expect_rows, has, not_has, crash} */
#define T1(n, has) {n, R, 1, ONE1, 0, -1, 1, has, NULL, false}

test_case_t suite[] = {
 /* ---- one fronthaul BSS: every property ---- */
 T1("ok_bssid", "1:BSSID=02:00:00:01:00:01\n"),
 T1("ok_ssid", "1:SSID=SSID1\n"),
 T1("ok_enabled", "1:Enabled=1\n"),
 T1("ok_byte_counter_units", "1:ByteCounterUnits=2\n"),
 T1("ok_fronthaul_use", "1:FronthaulUse=1\n"),
 T1("ok_backhaul_use", "1:BackhaulUse=0\n"),
 T1("ok_fronthaul_akms", "1:FronthaulAKMsAllowed=psk\n"),
 T1("ok_backhaul_akms_empty", "1:BackhaulAKMsAllowed=\n"),
 T1("ok_fronthaul_suite", "1:FronthaulSuiteSelector=0\n"),
 T1("ok_backhaul_suite", "1:BackhaulSuiteSelector=0\n"),
 T1("ok_sta_entries", "1:STANumberOfEntries=3\n"),
 T1("ok_sta_path", "0:sta_path=" R "1.STA.\n"),
 /* ---- backhaul BSS ---- */
 {"ok_backhaul_bss_use", R, 1, {S(1, false, 1, true, 0), E0, E0, E0, E0, E0}, 0, -1, 1, "1:BackhaulUse=1\n1:FronthaulUse=0\n", NULL, false},
 {"ok_backhaul_bss_akms", R, 1, {S(1, false, 1, true, 0), E0, E0, E0, E0, E0}, 0, -1, 1, "1:FronthaulAKMsAllowed=\n", "1:FronthaulAKMsAllowed=psk", false},
 {"ok_disabled_bss", R, 1, {S(1, false, 0, false, 0), E0, E0, E0, E0, E0}, 0, -1, 1, "1:Enabled=0\n", NULL, false},
 /* ---- which BSSs are listed and how they are numbered ---- */
 {"ok_no_bss", R, 1, {E0, E0, E0, E0, E0, E0}, 0, 0, 0, NULL, "BSSID", false},
 {"ok_two_bss_numbered", R, 1, {S(1, false, 0, true, 0), S(1, false, 1, true, 0), E0, E0, E0, E0}, 0, -1, 2, "2:BSSID=02:00:00:01:00:02\n", NULL, false},
 {"ok_second_sta_path", R, 1, {S(1, false, 0, true, 0), S(1, false, 1, true, 0), E0, E0, E0, E0}, 0, -1, 2, "0:sta_path=" R "2.STA.\n", NULL, false},
 {"ok_other_radio_skipped", R, 1, {S(2, false, 0, true, 0), E0, E0, E0, E0, E0}, 0, -1, 0, NULL, "BSSID", false},
 {"ok_zero_bssid_skipped", R, 1, {S(1, true, 0, true, 0), E0, E0, E0, E0, E0}, 0, -1, 0, NULL, "BSSID", false},
 {"ok_numbering_skips_zero_bssid", R, 1, {S(1, true, 0, true, 0), S(1, false, 0, true, 0), E0, E0, E0, E0}, 0, -1, 1, "1:BSSID=02:00:00:01:00:02\n", NULL, false},
 {"ok_numbering_skips_other_radio", R, 1, {S(1, false, 0, true, 0), S(2, false, 0, true, 0), S(1, false, 0, true, 0), E0, E0, E0}, 0, -1, 2, "2:BSSID=02:00:00:01:00:03\n", NULL, false},
 {"ok_radio2_listed", R, 2, {S(1, false, 0, true, 0), S(2, false, 0, true, 0), E0, E0, E0, E0}, 0, -1, 1, "1:BSSID=02:00:00:02:00:02\n", NULL, false},
 {"ok_radio3_listed", R, 3, {S(3, false, 0, true, 0), E0, E0, E0, E0, E0}, 0, -1, 1, "1:BSSID=02:00:00:03:00:01\n", NULL, false},
 {"ok_24_bss_full_table", R, 1, {E0, E0, E0, E0, E0, E0}, 24, 24, 24, "24:BSSID=", NULL, false},
 {"ok_long_root", "LONG", 1, ONE1, 0, -1, 1, "1:BSSID=02:00:00:01:00:01\n", NULL, false},
 /* ---- were CRASH cases on the original handler: raw m_num_bss above the 24-entry m_bss[] (now clamped to 24) ---- */
 {"clamp_num_bss_25", R, 1, {E0, E0, E0, E0, E0, E0}, 24, 25, 24, NULL, NULL, false},
 {"clamp_num_bss_255", R, 1, {E0, E0, E0, E0, E0, E0}, 24, 255, 24, NULL, NULL, false},
 {"clamp_num_bss_100000", R, 1, {E0, E0, E0, E0, E0, E0}, 24, 100000, 24, NULL, NULL, false},

 { NULL, NULL, 0, {E0, E0, E0, E0, E0, E0}, 0, 0, 0, NULL, NULL, false }  /* sentinel */
};

static void fill(dm_bss_t *b, int radio, bool zero, int haul, bool en, unsigned int nsta, int pos)
{
    em_bss_info_t *bi = &b->info;
    memset(bi, 0, sizeof(*bi));
    unsigned char ru[6] = {2, 0, 0, 0, 0, (unsigned char)radio};
    unsigned char bs[6] = {2, 0, 0, (unsigned char)radio, 0, (unsigned char)(pos + 1)};
    memcpy(bi->ruid.mac, ru, 6);
    if (!zero) memcpy(bi->bssid.mac, bs, 6);
    snprintf(bi->ssid, sizeof(bi->ssid), "SSID%d", pos + 1);
    bi->id.haul_type = haul ? em_haul_type_backhaul : em_haul_type_fronthaul;
    bi->enabled = en; bi->numberofsta = nsta; bi->byte_counter_units = 2;
}

void construct_input(const test_case_t *tc)
{
    memset(root_store, 0, sizeof(root_store));
    if (!strcmp(tc->root, "LONG")) memset(root_store + BTP_ROOT_LEFT, 'a', 600);
    else snprintf(root_store + BTP_ROOT_LEFT, BTP_ROOT_SZ, "%s", tc->root);
    g_rec[0] = '\0'; g_rows = 0;
    dm_easy_mesh_t *dm = new dm_easy_mesh_t;
    memset((void *)dm, 0, sizeof(*dm));
    unsigned int n = 0;
    if (tc->fill_all) {
        for (int i = 0; i < tc->fill_all && i < EM_MAX_BSSS; i++, n++) fill(&dm->m_bss[i], 1, false, 0, true, 0, i);
    } else {
        for (int i = 0; i < BTP_MAXSPEC; i++) {
            const bss_spec_t *s = &tc->bss[i];
            if (!s->radio) continue;
            fill(&dm->m_bss[i], s->radio, s->zero_bssid, s->haul, s->enabled, s->nsta, i);
            n = i + 1;
        }
    }
    dm->m_num_bss = tc->n_bss >= 0 ? (unsigned int)tc->n_bss : n;
    g_dm = dm;
}

void teardown(void)
{
    delete g_dm; g_dm = NULL;
}

} /* namespace btp */
