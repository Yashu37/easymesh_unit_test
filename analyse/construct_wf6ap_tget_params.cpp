/*
 * TEST CASES / CONSTRUCTOR: construct_wf6ap_tget_params
 *
 * root lives in root_store at offset WTP_ROOT_LEFT (runner poisons the bytes in front of it and past its
 * NUL). One radio (RUID 02:00:00:00:00:01) with a radio cap of num_role roles (only 2 are really stored,
 * MAP_AP_ROLE_MAX); the runner poisons the fields after roles[2]. Role data:
 *   role 0: HE160=1 HE8080=0 MCS maps (mcs_nss_num/4 of "12","ab","cd") and the tail bits alternate
 *           (dl_ofdma 1, ul_ofdma 0, ul_mumimo 1, ... rts 0), MaxDLMUMIMO 6, MaxULMUMIMO 5, MaxDLOFDMA 0, MaxULOFDMA 8
 *   role 1: the opposite bits, MaxDLOFDMA 1
 * The recorded property lines are "name=value" for every role in order (role 0 block, then role 1 block).
 *
 * Expected: always bus_error_success (0). The crash_* cases (num_role 3 / 255, above the 2 stored roles)
 * ABORT on the original handler (roles[i] read past the array): they run last and UNFORKED (a plain make
 * stops at the first ASan report); FORK_CRASH=1 runs each in a forked child so all of them show.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wf6ap_tget_params.h"

namespace wtp {

alignas(16) char root_store[WTP_ROOT_LEFT + WTP_ROOT_SZ + 64];

#define R "Device.WiFi.DataElements.Network.Device.1.Radio.1.Capabilities.WiFi6APRole."
/* {name, root, num_role, mcs_num, cap_present, other_radio, expect_roles, has, not_has, crash} */
#define T(n, nr, mcs, cap, oth, roles, has, nh) {n, R, nr, mcs, cap, oth, roles, has, nh, false}

test_case_t suite[] = {
 /* ---- every parameter name (role 0, one role) ---- */
 T("ok_HE160", 1, 8, true, false, 1, "HE160=1\n", NULL),
 T("ok_HE8080", 1, 8, true, false, 1, "HE8080=0\n", NULL),
 T("ok_MCSNSS", 1, 8, true, false, 1, "MCSNSS=12ab\n", NULL),
 T("ok_SUBeamformer", 1, 8, true, false, 1, "SUBeamformer=0\n", NULL),
 T("ok_SUBeamformee", 1, 8, true, false, 1, "SUBeamformee=1\n", NULL),
 T("ok_MUBeamformer", 1, 8, true, false, 1, "MUBeamformer=0\n", NULL),
 T("ok_Beamformee80orLess", 1, 8, true, false, 1, "Beamformee80orLess=1\n", NULL),
 T("ok_BeamformeeAbove80", 1, 8, true, false, 1, "BeamformeeAbove80=0\n", NULL),
 T("ok_ULMUMIMO", 1, 8, true, false, 1, "ULMUMIMO=1\n", NULL),
 T("ok_ULOFDMA", 1, 8, true, false, 1, "ULOFDMA=0\n", NULL),
 T("ok_DLOFDMA", 1, 8, true, false, 1, "DLOFDMA=1\n", NULL),
 T("ok_MaxDLMUMIMO", 1, 8, true, false, 1, "MaxDLMUMIMO=6\n", NULL),
 T("ok_MaxULMUMIMO", 1, 8, true, false, 1, "MaxULMUMIMO=5\n", NULL),
 T("ok_MaxDLOFDMA", 1, 8, true, false, 1, "MaxDLOFDMA=0\n", NULL),
 T("ok_MaxULOFDMA", 1, 8, true, false, 1, "MaxULOFDMA=8\n", NULL),
 T("ok_RTS", 1, 8, true, false, 1, "RTS=0\n", NULL),
 T("ok_MURTS", 1, 8, true, false, 1, "MURTS=1\n", NULL),
 T("ok_MultiBSSID", 1, 8, true, false, 1, "MultiBSSID=0\n", NULL),
 T("ok_MUEDCA", 1, 8, true, false, 1, "MUEDCA=1\n", NULL),
 T("ok_TWTRequestor", 1, 8, true, false, 1, "TWTRequestor=0\n", NULL),
 T("ok_TWTResponder", 1, 8, true, false, 1, "TWTResponder=1\n", NULL),
 T("ok_SpatialReuse", 1, 8, true, false, 1, "SpatialReuse=0\n", NULL),
 T("ok_AnticipatedChannelUsage", 1, 8, true, false, 1, "AnticipatedChannelUsage=1\n", NULL),
 /* ---- roles ---- */
 T("ok_two_roles_reported", 2, 8, true, false, 2, "HE160=0\nHE8080=1\n", NULL),
 T("ok_two_roles_second_maxdlofdma", 2, 8, true, false, 2, "MaxDLOFDMA=1\n", NULL),
 T("ok_two_roles_first_block_first", 2, 8, true, false, 2, "HE160=1\nHE8080=0\nMCSNSS=12ab\n", NULL),
 T("ok_no_roles", 0, 8, true, false, 0, NULL, "HE160"),
 /* ---- radio cap lookup ---- */
 T("ok_no_cap_entry", 1, 8, false, false, 0, NULL, "HE160"),
 T("ok_other_radio_no_cap", 1, 8, true, true, 0, NULL, "HE160"),
 /* ---- MCS / NSS maps (mcs_nss_num / 4, at most MAX_MCS = 3) ---- */
 T("ok_mcs_num_0", 1, 0, true, false, 1, "MCSNSS=\n", NULL),
 T("ok_mcs_num_3", 1, 3, true, false, 1, "MCSNSS=\n", NULL),
 T("ok_mcs_num_4", 1, 4, true, false, 1, "MCSNSS=12\n", NULL),
 T("ok_mcs_num_12", 1, 12, true, false, 1, "MCSNSS=12abcd\n", NULL),
 T("ok_mcs_num_15", 1, 15, true, false, 1, "MCSNSS=12abcd\n", NULL),
 {"ok_long_root", "LONG", 1, 8, true, false, 1, "HE160=1\n", NULL, false},
 /* ---- CRASH cases (run last, unforked): num_role above the 2 stored roles ---- */
 {"crash_num_role_3", R, 3, 8, true, false, 2, "HE160=0\n", NULL, true},
 {"crash_num_role_255", R, 255, 8, true, false, 2, "HE160=0\n", NULL, true},

 { NULL, NULL, 0, 0, false, false, 0, NULL, NULL, false }  /* sentinel */
};

static void fill_role(em_wifi6_role_wire_t *r, int k, int mcs)
{
    memset(r, 0, sizeof(*r));
    int s = (k == 0);                       /* role 0 = pattern, role 1 = inverted */
    r->role_head.mcs_nss_num = mcs;
    r->role_head.he_160 = s; r->role_head.he_8080 = !s;
    r->sprt_tx_rx_mcs[0].tx_he_mcs = 1;   r->sprt_tx_rx_mcs[0].rx_he_mcs = 2;
    r->sprt_tx_rx_mcs[1].tx_he_mcs = 0xa; r->sprt_tx_rx_mcs[1].rx_he_mcs = 0xb;
    r->sprt_tx_rx_mcs[2].tx_he_mcs = 0xc; r->sprt_tx_rx_mcs[2].rx_he_mcs = 0xd;
    r->role_tail.dl_ofdma = s;          r->role_tail.ul_ofdma = !s;
    r->role_tail.ul_mumimo = s;         r->role_tail.beam_formee_sts_g80 = !s;
    r->role_tail.beam_formee_sts_l80 = s; r->role_tail.mu_beam_former = !s;
    r->role_tail.su_beam_formee = s;    r->role_tail.su_beam_former = !s;
    r->role_tail.max_ul_mumimo_rx = 5;  r->role_tail.max_dl_mumimo_tx = 6;
    r->role_tail.max_dl_ofdma_tx = (unsigned char)k; r->role_tail.max_ul_ofdma_rx = 8;
    r->role_tail.anticipated_channel_usage = s; r->role_tail.spatial_reuse = !s;
    r->role_tail.twt_resp = s;          r->role_tail.twt_req = !s;
    r->role_tail.mu_edca = s;           r->role_tail.multi_bssid = !s;
    r->role_tail.mu_rts = s;            r->role_tail.rts = !s;
}

void construct_input(const test_case_t *tc)
{
    memset(root_store, 0, sizeof(root_store));
    if (!strcmp(tc->root, "LONG")) memset(root_store + WTP_ROOT_LEFT, 'a', 150);
    else snprintf(root_store + WTP_ROOT_LEFT, WTP_ROOT_SZ, "%s", tc->root);
    g_rec[0] = '\0'; g_roles = 0;
    dm_easy_mesh_t *dm = new dm_easy_mesh_t;
    memset((void *)dm, 0, sizeof(*dm));
    dm->cap.present = tc->cap_present;
    em_radio_wifi6_cap_data_t *w = &dm->cap.info.wifi6_cap;
    w->num_role = (unsigned char)tc->num_role;
    fill_role(&w->roles[0], 0, tc->mcs_num);
    fill_role(&w->roles[1], 1, tc->mcs_num);
    g_dm = dm;
}

void teardown(void)
{
    delete g_dm; g_dm = NULL;
}

} /* namespace wtp */
