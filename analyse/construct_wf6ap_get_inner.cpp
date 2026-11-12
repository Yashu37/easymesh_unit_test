/*
 * TEST CASES / CONSTRUCTOR: construct_wf6ap_get_inner
 *
 * event_name lives in name_store at offset W6G_LEFT (runner poisons the bytes in front of it and
 * past its NUL). Each case lists up to 4 data models (w6g::dm_spec_t: dm id, num_role, which radios
 * have a radio cap). Radio r of dm N has RUID 02:00:00:N:00:r+1. The role data is fixed:
 *   role 0: HE160=1 HE8080=0 mcs_nss_num=8 (2 maps "12","ab") and the tail bits alternate
 *           (dl_ofdma 1, ul_ofdma 0, ul_mumimo 1, ... rts 0), MaxDLMUMIMO 6, MaxULMUMIMO 5,
 *           MaxDLOFDMA 10*N, MaxULOFDMA 8
 *   role 1: the opposite bits, MaxDLOFDMA 10*N+1
 * so a wrong field mapping or the wrong data model shows in the recorded raw_data_set value.
 * Only 2 roles are really stored (MAP_AP_ROLE_MAX); the runner poisons the fields after them.
 *
 * expect_rc: 0 success, 2 invalid_input. Cases marked [spec] are wrong behaviour (no abort). The
 * crash_* cases ABORT on the original handler: they run last and UNFORKED (a plain make stops at
 * the first ASan report); FORK_CRASH=1 runs each in a forked child so all of them show.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wf6ap_get_inner.h"

namespace w6g {

alignas(16) char name_store[W6G_LEFT + W6G_NAME_SZ + W6G_PAD];

#define N "Device.WiFi.DataElements.Network."
#define EV(dev, rad, p) N "Device." dev ".Radio." rad ".WiFi6APRole." p
#define E0 {0, 0, false, false, false}
#define D1 {1, 1, true, false, false}
/* {name, event, no_pdata, dms[4], expect_rc, expect_val, check_val, crash} */
#define OKV(n, p, v) {n, EV("1", "1", p), false, {D1, E0, E0, E0}, 0, v, true, false}
#define RJ(n, ev, ...) {n, ev, false, {__VA_ARGS__}, 2, NULL, false, false}
#define CR(n, ev, ...) {n, ev, false, {__VA_ARGS__}, 2, NULL, false, true}

test_case_t suite[] = {
 /* ---- every parameter name (role 0) ---- */
 OKV("ok_HE160", "HE160", "1"),
 OKV("ok_HE8080", "HE8080", "0"),
 OKV("ok_MCSNSS", "MCSNSS", "12ab"),
 OKV("ok_SUBeamformer", "SUBeamformer", "0"),
 OKV("ok_SUBeamformee", "SUBeamformee", "1"),
 OKV("ok_MUBeamformer", "MUBeamformer", "0"),
 OKV("ok_Beamformee80orLess", "Beamformee80orLess", "1"),
 OKV("ok_BeamformeeAbove80", "BeamformeeAbove80", "0"),
 OKV("ok_ULMUMIMO", "ULMUMIMO", "1"),
 OKV("ok_ULOFDMA", "ULOFDMA", "0"),
 OKV("ok_DLOFDMA", "DLOFDMA", "1"),
 OKV("ok_MaxDLMUMIMO", "MaxDLMUMIMO", "6"),
 OKV("ok_MaxULMUMIMO", "MaxULMUMIMO", "5"),
 OKV("ok_MaxDLOFDMA", "MaxDLOFDMA", "10"),
 OKV("ok_MaxULOFDMA", "MaxULOFDMA", "8"),
 OKV("ok_RTS", "RTS", "0"),
 OKV("ok_MURTS", "MURTS", "1"),
 OKV("ok_MultiBSSID", "MultiBSSID", "0"),
 OKV("ok_MUEDCA", "MUEDCA", "1"),
 OKV("ok_TWTRequestor", "TWTRequestor", "0"),
 OKV("ok_TWTResponder", "TWTResponder", "1"),
 OKV("ok_SpatialReuse", "SpatialReuse", "0"),
 OKV("ok_AnticipatedChannelUsage", "AnticipatedChannelUsage", "1"),
 /* ---- roles / radios / devices ---- */
 {"ok_two_roles_last_wins", EV("1", "1", "HE160"), false, {{1, 2, true, false, false}, E0, E0, E0}, 0, "0", true, false},
 {"ok_radio_2", EV("1", "2", "HE160"), false, {{1, 1, true, true, false}, E0, E0, E0}, 0, "1", true, false},
 {"ok_device_1_of_2", EV("1", "1", "MaxDLOFDMA"), false, {{1, 1, true, false, false}, {2, 1, true, false, false}, E0, E0}, 0, "10", true, false},
 {"ok_device_2_of_2", EV("2", "1", "MaxDLOFDMA"), false, {{1, 1, true, false, false}, {2, 1, true, false, false}, E0, E0}, 0, "20", true, false},
 RJ("rej_invalid_param", EV("1", "1", "Foo"), D1, E0, E0, E0),
 RJ("rej_num_role_0", EV("1", "1", "HE160"), {1, 0, true, false, false}, E0, E0, E0),
 RJ("rej_radio_cap_missing", EV("1", "2", "HE160"), D1, E0, E0, E0),
 RJ("rej_device_not_found", EV("9", "1", "HE160"), D1, E0, E0, E0),
 {"rej_event_null", NULL, false, {D1, E0, E0, E0}, 2, NULL, false, false},
 {"rej_pdata_null", EV("1", "1", "HE160"), true, {D1, E0, E0, E0}, 2, NULL, false, false},
 RJ("rej_no_dot", "HE160", D1, E0, E0, E0),
 /* ---- [spec]: wrong behaviour, no abort (only the first two data models are looked at) ---- */
 {"rej_device_9_of_2 [spec]", EV("9", "1", "MaxDLOFDMA"), false, {{1, 1, true, false, false}, {2, 1, true, false, false}, E0, E0}, 2, NULL, false, false},
 {"ok_device_3_of_3 [spec]", EV("3", "1", "MaxDLOFDMA"), false, {{1, 1, true, false, false}, {2, 1, true, false, false}, {3, 1, true, false, false}, E0}, 0, "30", true, false},
 /* ---- CRASH cases (run last, unforked) ---- */
 CR("crash_method_short", "X.HE160", D1, E0, E0, E0),
 CR("crash_path_without_radio", N "Device.1.HE160", D1, E0, E0, E0),
 CR("crash_path_without_device", N "HE160", D1, E0, E0, E0),
 CR("crash_radio_0", EV("1", "0", "HE160"), D1, E0, E0, E0),
 CR("crash_radio_4", EV("1", "4", "HE160"), D1, E0, E0, E0),
 CR("crash_radio_huge", EV("1", "1000000", "HE160"), D1, E0, E0, E0),
 CR("crash_radio_alias", EV("1", "[x]", "HE160"), D1, E0, E0, E0),
 CR("crash_num_role_3", EV("1", "1", "HE160"), {1, 3, true, false, false}, E0, E0, E0),
 CR("crash_num_role_255", EV("1", "1", "HE160"), {1, 255, true, false, false}, E0, E0, E0),

 { NULL, NULL, false, {E0, E0, E0, E0}, 0, NULL, false, false }  /* sentinel */
};

static void fill_role(em_wifi6_role_wire_t *r, int k, int id)
{
    memset(r, 0, sizeof(*r));
    int s = (k == 0);                       /* role 0 = pattern, role 1 = inverted */
    r->role_head.mcs_nss_num = 8;
    r->role_head.he_160 = s; r->role_head.he_8080 = !s;
    r->sprt_tx_rx_mcs[0].tx_he_mcs = 1;   r->sprt_tx_rx_mcs[0].rx_he_mcs = 2;
    r->sprt_tx_rx_mcs[1].tx_he_mcs = 0xa; r->sprt_tx_rx_mcs[1].rx_he_mcs = 0xb;
    r->sprt_tx_rx_mcs[2].tx_he_mcs = 0xc; r->sprt_tx_rx_mcs[2].rx_he_mcs = 0xd;
    r->role_tail.dl_ofdma = s;          r->role_tail.ul_ofdma = !s;
    r->role_tail.ul_mumimo = s;         r->role_tail.beam_formee_sts_g80 = !s;
    r->role_tail.beam_formee_sts_l80 = s; r->role_tail.mu_beam_former = !s;
    r->role_tail.su_beam_formee = s;    r->role_tail.su_beam_former = !s;
    r->role_tail.max_ul_mumimo_rx = 5;  r->role_tail.max_dl_mumimo_tx = 6;
    r->role_tail.max_dl_ofdma_tx = (unsigned char)(10 * id + k); r->role_tail.max_ul_ofdma_rx = 8;
    r->role_tail.anticipated_channel_usage = s; r->role_tail.spatial_reuse = !s;
    r->role_tail.twt_resp = s;          r->role_tail.twt_req = !s;
    r->role_tail.mu_edca = s;           r->role_tail.multi_bssid = !s;
    r->role_tail.mu_rts = s;            r->role_tail.rts = !s;
}

void construct_input(const test_case_t *tc)
{
    memset(name_store, 0, sizeof(name_store));
    if (tc->event) snprintf(name_store + W6G_LEFT, W6G_NAME_SZ, "%s", tc->event);
    g_nset = 0; g_val[0] = '\0'; g_ndm = 0;
    for (int i = 0; i < W6G_MAXDM; i++) {
        const dm_spec_t *s = &tc->dms[i];
        if (!s->id) break;
        dm_easy_mesh_t *dm = new dm_easy_mesh_t;
        memset((void *)dm, 0, sizeof(*dm));
        dm->id = s->id;
        bool caps[3] = {s->cap0, s->cap1, s->cap2};
        for (int r = 0; r < EM_MAX_BANDS; r++) {
            unsigned char m[6] = {2, 0, 0, (unsigned char)s->id, 0, (unsigned char)(r + 1)};
            memcpy(dm->m_radio[r].info.id.ruid, m, 6);
            dm->has_cap[r] = caps[r];
            em_radio_wifi6_cap_data_t *w = &dm->cap[r].info.wifi6_cap;
            w->num_role = (unsigned char)s->num_role;
            fill_role(&w->roles[0], 0, s->id);
            fill_role(&w->roles[1], 1, s->id);
        }
        g_dm[g_ndm++] = dm;
    }
}

void teardown(void)
{
    for (int i = 0; i < g_ndm; i++) { delete g_dm[i]; g_dm[i] = NULL; }
    g_ndm = 0;
}

} /* namespace w6g */
