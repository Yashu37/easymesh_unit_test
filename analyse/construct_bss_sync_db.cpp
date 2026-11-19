/*
 * TEST CASES / CONSTRUCTOR: construct_bss_sync_db
 *
 * Scripted BSSList rows (21 columns): 1 ID "<net>@<dev mac>@<ruid>@<bssid>@<haul>", 2 BSSID, 3 RUID, 4 SSID, 5 Enabled 1, 6-9 EstServiceParameters,
 * 10 FronthaulAKMs, 11 BackhaulAKMs, 12-21 numbers. Column shorthand: "=" default, "@N" N list entries, "#N" N characters, NULL = SQL NULL.
 * Row 2 (nrows 2) repeats row 0 (variant 0) or has NULL BSSID / RUID (variant 1). Each string cell lives between poisoned guards (runner).
 * PASS = recorded BSSs, haul type, BSSID, SSID, AKM counts, timestamp untouched and the second-row BSSID.
 * Cases named crash_* ABORT on the original code (assert in get_strings_by_token for 11+ AKMs, stack overflow in get_string for an
 * ID / AKM list longer than str[128] or a MAC longer than mac[18]): they run last and UNFORKED so a plain `make` stops with the report;
 * FORK_CRASH=1 forks each one. A long SSID overwrites the following members of info (timestamp) without an ASan report. [spec] cases:
 * wrong behaviour, no abort.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bss_sync_db.h"

namespace bsd {
#define D "="
/* {name, id, bssid, ruid, ssid, fh, bh, nrows, row2_variant, updates, haul, bssid, ssid, nfh, nbh, ts_intact, row2_bssid_zero, crash} */
test_case_t suite[] = {
 {"ok_no_rows",                        D, D, D, D, D, D, 0, 0, 0, -1, NULL, NULL, -1, -1, 0, 0, false},
 {"ok_default_row",                    D, D, D, D, D, D, 1, 0, 1, 1, "aa:bb:cc:dd:ee:01", "MySsid", 2, 1, 1, 0, false},
 {"ok_one_akm_each",                   D, D, D, D, "psk", "sae", 1, 0, 1, 1, NULL, NULL, 1, 1, 1, 0, false},
 {"ok_ten_akms_max",                   D, D, D, D, "@10", "@10", 1, 0, 1, 1, NULL, NULL, 10, 10, 1, 0, false},
 {"ok_empty_akm_lists",                D, D, D, D, "", "", 1, 0, 1, 1, NULL, NULL, 0, 0, 1, 0, false},
 {"ok_ssid_31_chars",                  D, D, D, "#31", D, D, 1, 0, 1, 1, NULL, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 2, 1, 1, 0, false},
 {"ok_id_127_chars",                   "#127", D, D, D, D, D, 1, 0, 1, 0, NULL, NULL, 2, 1, 1, 0, false},
 {"ok_compact_macs",                   D, "aabbccddee01", "aabbccddee02", D, D, D, 1, 0, 1, 1, "aa:bb:cc:dd:ee:01", NULL, 2, 1, 1, 0, false},
 {"ok_mac_17_chars_fits_buffer",       D, D, D, D, D, D, 1, 0, 1, 1, "aa:bb:cc:dd:ee:01", NULL, 2, 1, 1, 0, false},
 {"ok_two_identical_rows",             D, D, D, D, D, D, 2, 0, 2, 1, NULL, NULL, 2, 1, 1, 0, false},
 /* ---- [spec]: wrong behaviour, no abort ---- */
 {"spec_null_mac_columns_must_not_keep_previous_row [spec]", D, D, D, D, D, D, 2, 1, 2, 1, NULL, NULL, 2, 1, 1, 1, false},
 {"clamp_ssid_100_chars_must_not_corrupt_timestamp",         D, D, D, "#100", D, D, 1, 0, 1, 1, NULL, NULL, 2, 1, 1, 0, false},
 /* ---- CRASH cases on the original code: run last, unforked ---- */
 {"crash_eleven_fronthaul_akms_assert", D, D, D, D, "@11", D, 1, 0, 1, 1, NULL, NULL, 10, 1, 1, 0, true},
 {"crash_eleven_backhaul_akms_assert",  D, D, D, D, D, "@11", 1, 0, 1, 1, NULL, NULL, 2, 10, 1, 0, true},
 {"crash_fronthaul_list_200_chars",     D, D, D, D, "#200", D, 1, 0, 1, 1, NULL, NULL, 1, 1, 1, 0, true},
 {"crash_backhaul_list_200_chars",      D, D, D, D, D, "#200", 1, 0, 1, 1, NULL, NULL, 2, 1, 1, 0, true},
 {"crash_id_200_chars",                 "#200", D, D, D, D, D, 1, 0, 1, 0, NULL, NULL, 2, 1, 1, 0, true},
 {"crash_id_4000_chars",                "#4000", D, D, D, D, D, 1, 0, 1, 0, NULL, NULL, 2, 1, 1, 0, true},
 {"crash_bssid_18_chars",               D, "aa:bb:cc:dd:ee:01x", D, D, D, D, 1, 0, 1, 1, NULL, NULL, 2, 1, 1, 0, true},
 {"crash_ruid_200_chars",               D, D, "#200", D, D, D, 1, 0, 1, 1, NULL, NULL, 2, 1, 1, 0, true},
 {NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, NULL, NULL, 0, 0, 0, 0, false}
};

static void set_str(cell_t *c, const char *v, const char *def, const char *kind)
{
    c->kind = 1;
    if (!strcmp(v, "=")) { snprintf(c->s, sizeof(c->s), "%s", def); return; }
    if (v[0] == '#') { size_t n = (size_t)atoi(v + 1); if (n >= BSD_CELL_SZ) n = BSD_CELL_SZ - 1; memset(c->s, 'x', n); c->s[n] = 0; return; }
    if (v[0] == '@') { int n = atoi(v + 1); c->s[0] = 0; for (int i = 0; i < n; i++) { char e[16]; snprintf(e, sizeof(e), "%s%s%d", i ? "," : "", kind, i); strcat(c->s, e); } return; }
    snprintf(c->s, sizeof(c->s), "%s", v);
}
static void fill_row(row_t *r, const test_case_t *tc)
{
    memset(r, 0, sizeof(*r));
    if (tc->id) set_str(&r->c[0], tc->id, "OneWifiMesh@02:00:00:00:00:01@02:00:00:00:00:02@02:00:00:00:00:03@1", "id");
    if (tc->bssid) set_str(&r->c[1], tc->bssid, "aa:bb:cc:dd:ee:01", "m");
    if (tc->ruid) set_str(&r->c[2], tc->ruid, "aa:bb:cc:dd:ee:02", "m");
    if (tc->ssid) set_str(&r->c[3], tc->ssid, "MySsid", "s");
    r->c[4].kind = 2; r->c[4].num = 1;
    for (int i = 5; i < 9; i++) set_str(&r->c[i], "0x10", "0x10", "e");
    if (tc->fh) set_str(&r->c[9], tc->fh, "psk,sae", "a");
    if (tc->bh) set_str(&r->c[10], tc->bh, "psk", "b");
    for (int i = 11; i < BSD_COLS; i++) { r->c[i].kind = 2; r->c[i].num = i; }
}
void construct_input(const test_case_t *tc)
{
    memset(g_rows, 0, sizeof(g_rows)); g_nrows = tc->nrows;
    for (int i = 0; i < tc->nrows; i++) fill_row(&g_rows[i], tc);
    if (tc->nrows >= 2 && tc->row2_variant == 1) { g_rows[1].c[1].kind = 0; g_rows[1].c[2].kind = 0; }
    dm_bss_list_t::g_updates.clear();
}
void teardown(void) { dm_bss_list_t::g_updates.clear(); }
} /* namespace bsd */
