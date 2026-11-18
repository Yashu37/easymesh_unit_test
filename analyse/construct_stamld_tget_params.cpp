/*
 * TEST CASES / CONSTRUCTOR: construct_stamld_tget_params
 *
 * smt::g_dm is heap allocated per case with guard arrays before and after m_assoc_sta_mld[64] (the runner
 * poisons them, the entries that are not in use and every STA's unread members). The AP MLD handed to the
 * handler is g_ami (mac 02:00:00:00:00:01). Entry i of the data model is built from mld[i] (then, past the
 * specified ones, a copy of mld[0]): ap_mld_mac_addr 02:00:00:00:00:<ap_mld>, mac 02:00:00:00:00:<mac>,
 * str/emlsr set, nstr/emlmr clear. The STA map holds the STAs of sta[] (id 02:00:00:00:00:<id>, bytes_tx = tx,
 * bytes_rx = rx).
 *
 * Expected output is from the intent of the table get: one row per STA MLD that belongs to the AP MLD (index
 * counts only those), STA counters come from the associated STA whose id EQUALS the STA MLD's MAC (zero when
 * there is none), then affsta_tget_params is called with "<root><idx>.AffiliatedSTA.".
 *
 * Cases marked [spec] are wrong behaviour (no abort): the handler picks the STA with memcmp(...) != 0, so it
 * takes the first associated STA whose id DIFFERS from the STA MLD's MAC. Cases crash_* ABORT on the original
 * function (run last and UNFORKED, FORK_CRASH=1 forks each): m_num_assoc_sta_mld above 64 (loop runs past
 * m_assoc_sta_mld[]) and NULL dm / ami / property (never checked; the current callers always pass them, so
 * these are defensive).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "stamld_tget_params.h"

namespace smt {

char root_store[SMT_ROOT_LEFT + SMT_ROOT_SZ + 64];
em_ap_mld_info_t g_ami;
static sta_map_t g_map;
static dm_sta_t g_stas[SMT_MAXSTA];

#define N SMT_MAXSTA
#define NOSTA {{false,0,0,0},{false,0,0,0},{false,0,0,0},{false,0,0,0}}
#define NOMLD {{0,0,0},{0,0,0},{0,0,0}}
/* {name, root, nmld, mld[3], sta[4], rows, has, not_has, no_dm, no_ami, no_prop, rc, crash} */
#define T(...) {__VA_ARGS__, false, false, false, 0, false}

test_case_t suite[] = {
 T("ok_no_mld", "R.", 0, NOMLD, NOSTA, 0, NULL, NULL),
 T("ok_one_mld_match", "R.", 1, {{1,0x11,2},{0,0,0},{0,0,0}}, NOSTA, 1, "1:MLDMACAddress=02:00:00:00:00:11\n", NULL),
 T("ok_affiliated_count", "R.", 1, {{1,0x11,2},{0,0,0},{0,0,0}}, NOSTA, 1, "1:AffiliatedSTANumberOfEntries=2\n", NULL),
 T("ok_is_bsta_zero", "R.", 1, {{1,0x11,0},{0,0,0},{0,0,0}}, NOSTA, 1, "1:IsbSTA=0\n", NULL),
 T("ok_other_ap_mld_skipped", "R.", 1, {{9,0x11,0},{0,0,0},{0,0,0}}, NOSTA, 0, NULL, NULL),
 T("ok_idx_counts_only_matches", "R.", 3, {{1,0x11,0},{9,0x12,0},{1,0x13,0}}, NOSTA, 2, "2:MLDMACAddress=02:00:00:00:00:13\n", "3:MLDMACAddress"),
 T("ok_skipped_in_the_middle_not_listed", "R.", 3, {{9,0x11,0},{1,0x12,0},{9,0x13,0}}, NOSTA, 1, "1:MLDMACAddress=02:00:00:00:00:12\n", NULL),
 T("ok_config_str", "R.", 1, {{1,0x11,0},{0,0,0},{0,0,0}}, NOSTA, 1, "1:STAMLDConfig.STRSupport=1\n", NULL),
 T("ok_config_nstr", "R.", 1, {{1,0x11,0},{0,0,0},{0,0,0}}, NOSTA, 1, "1:STAMLDConfig.NSTRSupport=0\n", NULL),
 T("ok_config_emlsr", "R.", 1, {{1,0x11,0},{0,0,0},{0,0,0}}, NOSTA, 1, "1:STAMLDConfig.EMLSRSupport=1\n", NULL),
 T("ok_config_emlmr", "R.", 1, {{1,0x11,0},{0,0,0},{0,0,0}}, NOSTA, 1, "1:STAMLDConfig.EMLMRSupport=0\n", NULL),
 T("ok_wifi7_caps_str", "R.", 1, {{1,0x11,0},{0,0,0},{0,0,0}}, NOSTA, 1, "1:WiFi7Capabilities.STRSupport=1\n", NULL),
 T("ok_wifi7_caps_nstr", "R.", 1, {{1,0x11,0},{0,0,0},{0,0,0}}, NOSTA, 1, "1:WiFi7Capabilities.NSTRSupport=0\n", NULL),
 T("ok_counters_zero_without_sta", "R.", 1, {{1,0x11,0},{0,0,0},{0,0,0}}, NOSTA, 1, "1:BytesSent=0\n", NULL),
 T("ok_last_connect_zero_without_sta", "R.", 1, {{1,0x11,0},{0,0,0},{0,0,0}}, NOSTA, 1, "1:LastConnectTime=0\n", NULL),
 T("ok_unassociated_sta_ignored", "R.", 1, {{1,0x11,0},{0,0,0},{0,0,0}}, {{false,0x22,222,2},{false,0,0,0},{false,0,0,0},{false,0,0,0}}, 1, "1:BytesSent=0\n", NULL),
 T("ok_affsta_path", "R.", 1, {{1,0x11,0},{0,0,0},{0,0,0}}, NOSTA, 1, "0:AFFPATH=R.1.AffiliatedSTA.\n", NULL),
 T("ok_affsta_path_second_row", "R.", 3, {{1,0x11,0},{9,0x12,0},{1,0x13,0}}, NOSTA, 2, "0:AFFPATH=R.2.AffiliatedSTA.\n", NULL),
 T("ok_affsta_path_long_root", "Device.WiFi.DataElements.Network.Device.1.APMLD.1.STAMLD.", 1, {{1,0x11,0},{0,0,0},{0,0,0}}, NOSTA, 1, ".1.AffiliatedSTA.\n", NULL),
 T("ok_empty_root", "", 1, {{1,0x11,0},{0,0,0},{0,0,0}}, NOSTA, 1, "0:AFFPATH=1.AffiliatedSTA.\n", NULL),
 T("ok_root_600_chars_truncated_path", "LONG", 1, {{1,0x11,0},{0,0,0},{0,0,0}}, NOSTA, 1, "1:MLDMACAddress=02:00:00:00:00:11\n", NULL),
 T("ok_64_mlds_all_match", "R.", 64, {{1,0x11,0},{0,0,0},{0,0,0}}, NOSTA, 64, "64:MLDMACAddress=", NULL),
 T("ok_63_mlds", "R.", 63, {{1,0x11,0},{0,0,0},{0,0,0}}, NOSTA, 63, NULL, "64:MLDMACAddress"),
 /* ---- [spec]: wrong behaviour, no abort (the STA is picked with memcmp != 0) ---- */
 T("spec_sta_matched_by_id [spec]", "R.", 1, {{1,0x11,0},{0,0,0},{0,0,0}}, {{true,0x22,222,2},{true,0x11,111,1},{false,0,0,0},{false,0,0,0}}, 1, "1:BytesSent=111\n", NULL),
 T("spec_only_matching_sta [spec]", "R.", 1, {{1,0x11,0},{0,0,0},{0,0,0}}, {{true,0x11,111,1},{false,0,0,0},{false,0,0,0},{false,0,0,0}}, 1, "1:BytesSent=111\n", NULL),
 T("spec_other_sta_not_counted [spec]", "R.", 1, {{1,0x11,0},{0,0,0},{0,0,0}}, {{true,0x22,222,2},{false,0,0,0},{false,0,0,0},{false,0,0,0}}, 1, "1:BytesSent=0\n", "1:BytesSent=222"),
 /* ---- CRASH cases on the original function (rejected / clamped after the fix) ---- */
 {"crash_num_mlds_65", "R.", 65, {{1,0x11,0},{0,0,0},{0,0,0}}, NOSTA, 64, "64:MLDMACAddress=", "65:MLDMACAddress", false, false, false, 0, true},
 {"crash_num_mlds_1000", "R.", 1000, {{1,0x11,0},{0,0,0},{0,0,0}}, NOSTA, 64, NULL, "65:MLDMACAddress", false, false, false, 0, true},
 {"crash_null_dm", "R.", 1, {{1,0x11,0},{0,0,0},{0,0,0}}, NOSTA, 0, NULL, NULL, true, false, false, 2, true},
 {"crash_null_ami", "R.", 1, {{1,0x11,0},{0,0,0},{0,0,0}}, NOSTA, 0, NULL, NULL, false, true, false, 2, true},
 {"crash_null_property", "R.", 1, {{1,0x11,0},{0,0,0},{0,0,0}}, NOSTA, 0, NULL, NULL, false, false, true, 2, true},

 { NULL, NULL, 0, NOMLD, NOSTA, 0, NULL, NULL, false, false, false, 0, false }  /* sentinel */
};

static void mkmac(unsigned char *m, unsigned char last) { m[0] = 0x02; m[1] = m[2] = m[3] = m[4] = 0; m[5] = last; }

void construct_input(const test_case_t *tc)
{
    g_rec[0] = '\0'; g_rows = 0; g_aff_calls = 0; g_aff_path[0] = '\0'; g_dm = NULL;
    memset(root_store, 'R', sizeof(root_store));
    if (!strcmp(tc->root, "LONG")) { memset(root_store + SMT_ROOT_LEFT, 'a', 600); root_store[SMT_ROOT_LEFT + 600] = '\0'; }
    else snprintf(root_store + SMT_ROOT_LEFT, SMT_ROOT_SZ, "%s", tc->root);
    memset(&g_ami, 0, sizeof(g_ami)); mkmac(g_ami.mac_addr, 1);
    g_dm = (dm_easy_mesh_t *)calloc(1, sizeof(dm_easy_mesh_t));
    g_dm->m_num_assoc_sta_mld = (unsigned int)tc->nmld;
    for (int i = 0; i < tc->nmld && i < SMT_MAXMLD; i++) {
        const mld_spec_t *s = (i < 3 && tc->mld[i].mac) ? &tc->mld[i] : &tc->mld[0];
        em_assoc_sta_mld_info_t *e = g_dm->m_assoc_sta_mld[i].get_assoc_sta_mld_info();
        mkmac(e->ap_mld_mac_addr, s->ap_mld); mkmac(e->mac_addr, s->mac);
        e->str = true; e->nstr = false; e->emlsr = true; e->emlmr = false; e->num_affiliated_sta = (unsigned char)s->naff;
    }
    memset(g_stas, 0, sizeof(g_stas)); g_map.n = 0;
    for (int i = 0; i < SMT_MAXSTA; i++) {
        if (!tc->sta[i].id) continue;
        em_sta_info_t *si = g_stas[i].get_sta_info();
        mkmac(si->id, tc->sta[i].id); si->associated = tc->sta[i].assoc; si->bytes_tx = tc->sta[i].tx; si->bytes_rx = tc->sta[i].rx;
        g_map.p[g_map.n++] = &g_stas[i];
    }
    g_dm->m_sta_map = &g_map;
}

void teardown(void) { free(g_dm); g_dm = NULL; }

} /* namespace smt */
