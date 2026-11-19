/*
 * TEST CASES / CONSTRUCTOR: construct_apmld_tget_params
 *
 * apt::g_dm is heap allocated per case with guard arrays before and after m_ap_mld[64] (the runner poisons
 * them, the entries that are not in use and every entry's unread members). Entry i is built from mld[i]
 * (then, past the specified ones, a copy of mld[0]): mac 02:00:00:00:00:<mac>, str / emlsr set, nstr /
 * emlmr clear, num_affiliated_ap = naff.
 *
 * Expected output is from the intent of the table get: one row per AP MLD (MLDMACAddress,
 * AffiliatedAPNumberOfEntries, STAMLDNumberOfEntries, the four APMLDConfig flags), then affap_tget_params is
 * called with "<root><idx>.AffiliatedAP." and stamld_tget_params with "<root><idx>.STAMLD.".
 *
 * The case marked [spec] is wrong behaviour (no abort): STAMLDNumberOfEntries is the constant 0 although the
 * data model holds STA MLDs for the AP MLD (the STAMLD sub-table that follows lists them).
 * Cases crash_* ABORT on the original function (run last and UNFORKED, FORK_CRASH=1 forks each):
 * m_num_ap_mld above 64 (loop runs past m_ap_mld[]) and NULL dm / property (never checked; the current
 * callers always pass them, so these are defensive).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "apmld_tget_params.h"

namespace apt {

char root_store[APT_ROOT_LEFT + APT_ROOT_SZ + 64];

#define NOMLD {{0,0},{0,0},{0,0}}
/* {name, root, nmld, mld[3], n_stamld, rows, has, not_has, no_dm, no_prop, rc, crash} */
#define T(...) {__VA_ARGS__, false, false, 0, false}

test_case_t suite[] = {
 T("ok_no_mld", "R.", 0, NOMLD, 0, 0, NULL, NULL),
 T("ok_one_mld", "R.", 1, {{0x11,2},{0,0},{0,0}}, 0, 1, "1:MLDMACAddress=02:00:00:00:00:11\n", NULL),
 T("ok_two_mlds", "R.", 2, {{0x11,2},{0x12,3},{0,0}}, 0, 2, "2:MLDMACAddress=02:00:00:00:00:12\n", NULL),
 T("ok_affiliated_count", "R.", 2, {{0x11,2},{0x12,3},{0,0}}, 0, 2, "2:AffiliatedAPNumberOfEntries=3\n", NULL),
 T("ok_affiliated_count_first", "R.", 2, {{0x11,2},{0x12,3},{0,0}}, 0, 2, "1:AffiliatedAPNumberOfEntries=2\n", NULL),
 T("ok_stamld_count_zero_without_stas", "R.", 1, {{0x11,0},{0,0},{0,0}}, 0, 1, "1:STAMLDNumberOfEntries=0\n", NULL),
 T("ok_config_emlmr", "R.", 1, {{0x11,0},{0,0},{0,0}}, 0, 1, "1:APMLDConfig.EMLMREnabled=0\n", NULL),
 T("ok_config_emlsr", "R.", 1, {{0x11,0},{0,0},{0,0}}, 0, 1, "1:APMLDConfig.EMLSREnabled=1\n", NULL),
 T("ok_config_str", "R.", 1, {{0x11,0},{0,0},{0,0}}, 0, 1, "1:APMLDConfig.STREnabled=1\n", NULL),
 T("ok_config_nstr", "R.", 1, {{0x11,0},{0,0},{0,0}}, 0, 1, "1:APMLDConfig.NSTREnabled=0\n", NULL),
 T("ok_affap_path", "R.", 1, {{0x11,0},{0,0},{0,0}}, 0, 1, "0:AFFPATH=R.1.AffiliatedAP.\n", NULL),
 T("ok_stamld_path", "R.", 1, {{0x11,0},{0,0},{0,0}}, 0, 1, "0:STAPATH=R.1.STAMLD.\n", NULL),
 T("ok_affap_path_second_row", "R.", 2, {{0x11,0},{0x12,0},{0,0}}, 0, 2, "0:AFFPATH=R.2.AffiliatedAP.\n", NULL),
 T("ok_stamld_path_second_row", "R.", 2, {{0x11,0},{0x12,0},{0,0}}, 0, 2, "0:STAPATH=R.2.STAMLD.\n", NULL),
 T("ok_path_with_device_root", "Device.WiFi.DataElements.Network.APMLD.", 1, {{0x11,0},{0,0},{0,0}}, 0, 1, "0:AFFPATH=Device.WiFi.DataElements.Network.APMLD.1.AffiliatedAP.\n", NULL),
 T("ok_empty_root", "", 1, {{0x11,0},{0,0},{0,0}}, 0, 1, "0:AFFPATH=1.AffiliatedAP.\n", NULL),
 T("ok_root_600_chars_truncated_path", "LONG", 1, {{0x11,0},{0,0},{0,0}}, 0, 1, "1:MLDMACAddress=02:00:00:00:00:11\n", NULL),
 T("ok_64_mlds", "R.", 64, {{0x11,0},{0,0},{0,0}}, 0, 64, "64:MLDMACAddress=", NULL),
 T("ok_63_mlds", "R.", 63, {{0x11,0},{0,0},{0,0}}, 0, 63, NULL, "64:MLDMACAddress"),
 T("ok_idx_matches_entry_order", "R.", 3, {{0x11,0},{0x12,0},{0x13,0}}, 0, 3, "3:MLDMACAddress=02:00:00:00:00:13\n", NULL),
 /* ---- [spec]: wrong behaviour, no abort (STAMLDNumberOfEntries is the constant 0) ---- */
 T("spec_stamld_count_hardcoded_zero [spec]", "R.", 1, {{0x11,0},{0,0},{0,0}}, 2, 1, "1:STAMLDNumberOfEntries=2\n", NULL),
 /* ---- CRASH cases on the original function (clamped / rejected after the fix) ---- */
 {"crash_num_mlds_65", "R.", 65, {{0x11,0},{0,0},{0,0}}, 0, 64, "64:MLDMACAddress=", "65:MLDMACAddress", false, false, 0, true},
 {"crash_num_mlds_1000", "R.", 1000, {{0x11,0},{0,0},{0,0}}, 0, 64, NULL, "65:MLDMACAddress", false, false, 0, true},
 {"crash_null_dm", "R.", 1, {{0x11,0},{0,0},{0,0}}, 0, 0, NULL, NULL, true, false, 2, true},
 {"crash_null_property", "R.", 1, {{0x11,0},{0,0},{0,0}}, 0, 0, NULL, NULL, false, true, 2, true},

 { NULL, NULL, 0, NOMLD, 0, 0, NULL, NULL, false, false, 0, false }  /* sentinel */
};

static void mkmac(unsigned char *m, unsigned char last) { m[0] = 0x02; m[1] = m[2] = m[3] = m[4] = 0; m[5] = last; }

void construct_input(const test_case_t *tc)
{
    g_rec[0] = '\0'; g_rows = 0; g_aff_path[0] = '\0'; g_dm = NULL;
    memset(root_store, 'R', sizeof(root_store));
    if (!strcmp(tc->root, "LONG")) { memset(root_store + APT_ROOT_LEFT, 'a', 600); root_store[APT_ROOT_LEFT + 600] = '\0'; }
    else snprintf(root_store + APT_ROOT_LEFT, APT_ROOT_SZ, "%s", tc->root);
    g_dm = (dm_easy_mesh_t *)calloc(1, sizeof(dm_easy_mesh_t));
    g_dm->m_num_ap_mld = (unsigned int)tc->nmld;
    g_dm->n_stamld = (unsigned int)tc->n_stamld;
    for (int i = 0; i < tc->nmld && i < APT_MAXMLD; i++) {
        const mld_spec_t *s = (i < 3 && tc->mld[i].mac) ? &tc->mld[i] : &tc->mld[0];
        em_ap_mld_info_t *e = g_dm->m_ap_mld[i].get_ap_mld_info();
        mkmac(e->mac_addr, (i < 3 && tc->mld[i].mac) ? s->mac : (unsigned char)(0x20 + i));
        if (i >= 3 || !tc->mld[i].mac) mkmac(e->mac_addr, (unsigned char)(0x20 + i));
        e->str = true; e->nstr = false; e->emlsr = true; e->emlmr = false; e->num_affiliated_ap = (unsigned char)s->naff;
    }
    if (tc->nmld > 0 && tc->mld[0].mac && tc->nmld >= 64) mkmac(g_dm->m_ap_mld[0].get_ap_mld_info()->mac_addr, tc->mld[0].mac);
}

void teardown(void) { free(g_dm); g_dm = NULL; }

} /* namespace apt */
