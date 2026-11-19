/*
 * TEST CASES / CONSTRUCTOR: construct_network_ssid_sync_db
 *
 * Scripted NetworkSSIDList rows (13 columns): 1 ID, 2 SSID, 3 PassPhrase, 4 Band list, 5 Enable 1, 6 AKM list, 7 SuiteSelector,
 * 8 Advertisement 1, 9 MFP, 10 MobilityDomain MAC, 11 Haul list, 12 AuthType, 13 VLAN 5. Column shorthand in a case: "=" default,
 * "@N" N entries of a list (b0,b1.. / a0,a1.. / Fronthaul,Fronthaul..), "#N" N characters, NULL = SQL NULL. Each string cell lives
 * between poisoned guards (runner). PASS = recorded networks, num_bands / num_akms / num_hauls and the first two haul types.
 * Cases named clamp_* ABORTED on the original code (assert in get_strings_by_token for too many list entries, stack overflow in
 * get_string for a value longer than its buffer): fix 1 bounds the get_string copies, fix 2 ignores surplus list entries.
 * [spec] cases: wrong behaviour, no abort.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "network_ssid_sync_db.h"

namespace nss {
#define D "="
#define H(x) ((int)(x))
/* {name, id, ssid, pass, bands, akms, suite, mfp, mac, hauls, auth, nrows, updates, nb, na, nh, h0, h1, crash} */
test_case_t suite[] = {
 {"ok_no_rows",                      D, D, D, D, D, D, D, D, D, D, 0, 0, -1, -1, -1, -1, -1, false},
 {"ok_default_row",                  D, D, D, D, D, D, D, D, D, D, 1, 1, 2, 2, 2, H(em_haul_type_fronthaul), H(em_haul_type_backhaul), false},
 {"ok_one_band",                     D, D, D, "5GHz", D, D, D, D, D, D, 1, 1, 1, 2, 2, -1, -1, false},
 {"ok_three_bands_max",              D, D, D, "@3", D, D, D, D, D, D, 1, 1, 3, 2, 2, -1, -1, false},
 {"ok_ten_akms_max",                 D, D, D, D, "@10", D, D, D, D, D, 1, 1, 2, 10, 2, -1, -1, false},
 {"ok_eight_hauls_max",              D, D, D, D, D, D, D, D, "@8", D, 1, 1, 2, 2, 8, H(em_haul_type_fronthaul), H(em_haul_type_fronthaul), false},
 {"ok_empty_lists",                  D, D, D, "", "", D, D, D, "", D, 1, 1, 0, 0, 0, -1, -1, false},
 {"ok_all_haul_names",               D, D, D, D, D, D, D, D, "Fronthaul,Backhaul,IoT,Configurator,Hotspot", D, 1, 1, 2, 2, 5, H(em_haul_type_fronthaul), H(em_haul_type_backhaul), false},
 {"ok_unknown_haul_is_max",          D, D, D, D, D, D, D, D, "Foo", D, 1, 1, 2, 2, 1, H(em_haul_type_max), -1, false},
 {"ok_ssid_31_chars",                D, "#31", D, D, D, D, D, D, D, D, 1, 1, 2, 2, 2, -1, -1, false},
 {"ok_id_127_chars",                 "#127", D, D, D, D, D, D, D, D, D, 1, 1, 2, 2, 2, -1, -1, false},
 {"ok_pass_phrase_127_chars",        D, D, "#127", D, D, D, D, D, D, D, 1, 1, 2, 2, 2, -1, -1, false},
 {"ok_auth_type_31_chars",           D, D, D, D, D, D, D, D, D, "#31", 1, 1, 2, 2, 2, -1, -1, false},
 {"ok_compact_mac",                  D, D, D, D, D, D, D, "aabbccddee01", D, D, 1, 1, 2, 2, 2, -1, -1, false},
 {"ok_null_ssid_column",             D, NULL, D, D, D, D, D, D, D, D, 1, 1, 2, 2, 2, -1, -1, false},
 {"ok_two_rows",                     D, D, D, D, D, D, D, D, D, D, 2, 2, 2, 2, 2, -1, -1, false},
 /* ---- [spec]: wrong behaviour, no abort ---- */
 {"spec_empty_haul_token_must_not_be_fronthaul [spec]", D, D, D, D, D, D, D, D, "Backhaul,", D, 1, 1, 2, 2, 2, H(em_haul_type_backhaul), H(em_haul_type_max), false},
 /* ---- were CRASH cases on the original code ---- */
 {"clamp_four_bands_assert",         D, D, D, "@4", D, D, D, D, D, D, 1, 1, 3, 2, 2, -1, -1, false},
 {"clamp_eleven_akms_assert",        D, D, D, D, "@11", D, D, D, D, D, 1, 1, 2, 10, 2, -1, -1, false},
 {"clamp_nine_hauls_assert",         D, D, D, D, D, D, D, D, "@9", D, 1, 1, 2, 2, 8, -1, -1, false},
 {"clamp_twenty_short_hauls_assert",        D, D, D, D, D, D, D, D, "a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a", D, 1, 1, 2, 2, 8, -1, -1, false},
 {"clamp_band_list_200_chars",       D, D, D, "#200", D, D, D, D, D, D, 1, 1, 1, 2, 2, -1, -1, false},
 {"clamp_akm_list_200_chars",        D, D, D, D, "#200", D, D, D, D, D, 1, 1, 2, 1, 2, -1, -1, false},
 {"clamp_haul_list_200_chars",       D, D, D, D, D, D, D, D, "#200", D, 1, 1, 2, 2, 1, -1, -1, false},
 {"clamp_mobility_mac_18_chars",     D, D, D, D, D, D, D, "aa:bb:cc:dd:ee:01x", D, D, 1, 1, 2, 2, 2, -1, -1, false},
 {"clamp_mobility_mac_200_chars",    D, D, D, D, D, D, D, "#200", D, D, 1, 1, 2, 2, 2, -1, -1, false},
 {"clamp_auth_type_100_chars",       D, D, D, D, D, D, D, D, D, "#100", 1, 1, 2, 2, 2, -1, -1, false},
 {"clamp_id_1500_chars",             "#1500", D, D, D, D, D, D, D, D, D, 1, 1, 2, 2, 2, -1, -1, false},
 {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, 0, 0, false}
};

static void set_str(cell_t *c, const char *v, const char *def, const char *kind)
{
    c->kind = 1;
    if (!strcmp(v, "=")) { snprintf(c->s, sizeof(c->s), "%s", def); return; }
    if (v[0] == '#') { size_t n = (size_t)atoi(v + 1); if (n >= NSS_CELL_SZ) n = NSS_CELL_SZ - 1; memset(c->s, 'x', n); c->s[n] = 0; return; }
    if (v[0] == '@') {
        int n = atoi(v + 1); c->s[0] = 0;
        for (int i = 0; i < n; i++) {
            char e[40];
            if (!strcmp(kind, "haul")) snprintf(e, sizeof(e), "%sFronthaul", i ? "," : "");
            else snprintf(e, sizeof(e), "%s%s%d", i ? "," : "", kind, i);
            if (strlen(c->s) + strlen(e) < NSS_CELL_SZ) strcat(c->s, e);
        }
        return;
    }
    snprintf(c->s, sizeof(c->s), "%s", v);
}
static void put(cell_t *c, const char *v, const char *def, const char *kind) { if (v) set_str(c, v, def, kind); }
static void fill_row(row_t *r, const test_case_t *tc)
{
    memset(r, 0, sizeof(*r));
    put(&r->c[0], tc->id, "ssid1@net", "id"); put(&r->c[1], tc->ssid, "MySsid", "s"); put(&r->c[2], tc->pass, "secret123", "p");
    put(&r->c[3], tc->bands, "5GHz,2.4GHz", "b"); r->c[4].kind = 2; r->c[4].num = 1;
    put(&r->c[5], tc->akms, "psk,sae", "a"); r->c[7].kind = 2; r->c[7].num = 1;
    set_str(&r->c[6], "00-0F-AC", "00-0F-AC", "s"); put(&r->c[8], tc->mfp, "Required", "m"); put(&r->c[9], tc->mac, "aa:bb:cc:dd:ee:01", "mac");
    put(&r->c[10], tc->hauls, "Fronthaul,Backhaul", "haul"); put(&r->c[11], tc->auth, "Open", "auth"); r->c[12].kind = 2; r->c[12].num = 5;
}
void construct_input(const test_case_t *tc)
{
    memset(g_rows, 0, sizeof(g_rows)); g_nrows = tc->nrows;
    for (int i = 0; i < tc->nrows; i++) fill_row(&g_rows[i], tc);
    dm_network_ssid_list_t::g_updates.clear();
}
void teardown(void) { dm_network_ssid_list_t::g_updates.clear(); }
} /* namespace nss */
