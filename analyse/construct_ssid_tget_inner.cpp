/*
 * TEST CASES / CONSTRUCTOR: construct_ssid_tget_inner
 *
 * The data model sti::g_dm is heap allocated per case with guard arrays before and after
 * m_network_ssid[EM_MAX_NET_SSIDS = 5] (the runner poisons them and every entry's id[] / pass_phrase[]).
 * m_num_net_ssids = nssid (raw), the first min(nssid, 5) entries are filled: ssid "net<i>", bands
 * "2.4GHz,5GHz", akms "psk,sae", hauls Fronthaul,Backhaul, vlan 100 + i. event_name is copied into
 * name_store with poisoned bytes before and after (STI_LEFT).
 *
 * Expected output is from the documented behaviour of the table get: a partial path ending in '.'
 * returns one "idx:Name=value" group per SSID (SSID, Band, Enable, AKMsAllowed, SuiteSelector,
 * AdvertisementEnabled, MFPConfig, MobilityDomain, HaulType, AuthType, VLANID), a path not ending in '.'
 * is invalid_operation (6), the num_* counts are clamped to the arrays.
 *
 * Cases crash_* ABORT on the original function (they run last and UNFORKED so a plain make stops with the
 * ASan report; FORK_CRASH=1 forks each one): empty event_name (event_name[-1]), NULL event_name (strlen),
 * no data model (dm NULL dereferenced), p_data NULL (raw_data_set), m_num_net_ssids above 5 (loop runs past
 * m_network_ssid[]).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "ssid_tget_inner.h"

namespace sti {

char name_store[STI_LEFT + STI_NAME_SZ + STI_PAD];

#define P "Device.WiFi.DataElements.Network.SSID."
/* {name, event, no_pdata, no_dm, nssid, variant, rc, ids, has, not_has, crash} */
#define OK(n, ev, ns, var, ids, has, nh) {n, ev, false, false, ns, var, 0, ids, has, nh, false}

test_case_t suite[] = {
 /* ---- normal tables ---- */
 OK("ok_one_ssid", P, 1, 0, 1, "1:SSID=net0\n", NULL),
 OK("ok_two_ssids", P, 2, 0, 2, "2:SSID=net1\n", NULL),
 OK("ok_five_ssids_max", P, 5, 0, 5, "5:SSID=net4\n", NULL),
 OK("ok_zero_ssids", P, 0, 0, 0, NULL, NULL),
 OK("ok_band_list", P, 1, 0, 1, "1:Band=2.4GHz,5GHz\n", NULL),
 OK("ok_enable", P, 1, 0, 1, "1:Enable=1\n", NULL),
 OK("ok_akms_list", P, 1, 0, 1, "1:AKMsAllowed=psk,sae\n", NULL),
 OK("ok_haul_list", P, 1, 0, 1, "1:HaulType=Fronthaul,Backhaul\n", NULL),
 OK("ok_vlan", P, 2, 0, 2, "2:VLANID=101\n", NULL),
 OK("ok_suite_select", P, 1, 0, 1, "1:SuiteSelector=00-0F-AC\n", NULL),
 OK("ok_advertisement", P, 1, 0, 1, "1:AdvertisementEnabled=1\n", NULL),
 OK("ok_mfp", P, 1, 0, 1, "1:MFPConfig=required\n", NULL),
 OK("ok_auth_type", P, 1, 0, 1, "1:AuthType=sae\n", NULL),
 OK("ok_mobility_domain", P, 1, 0, 1, "1:MobilityDomain=aa:bb:cc:dd:ee:ff\n", NULL),
 OK("ok_pass_phrase_not_exported", P, 2, 0, 2, NULL, "secret"),
 OK("ok_short_root", "x.", 1, 0, 1, "1:SSID=net0\n", NULL),
 OK("ok_root_dots", "a.b.c.", 1, 0, 1, "1:SSID=net0\n", NULL),
 /* ---- num_* counts are clamped to the arrays ---- */
 OK("clamp_num_bands_200", P, 1, 1, 1, "1:Band=2.4GHz,5GHz,6GHz\n", NULL),
 OK("clamp_num_akms_200", P, 1, 2, 1, "1:AKMsAllowed=k0,k1,k2,k3,k4,k5,k6,k7,k8,k9\n", NULL),
 OK("clamp_num_hauls_200", P, 1, 3, 1, "1:HaulType=Fronthaul,Fronthaul,Fronthaul,Fronthaul,Fronthaul,Fronthaul,Fronthaul,Fronthaul\n", NULL),
 OK("ok_unknown_haul_stops_list", P, 1, 4, 1, "1:HaulType=Fronthaul,Backhaul\n", NULL),
 OK("ok_empty_first_band", P, 1, 5, 1, "1:Band=\n", NULL),
 /* ---- invalid paths ---- */
 {"rej_no_trailing_dot", P "1", false, false, 1, 0, 6, 0, NULL, NULL, false},
 {"rej_trailing_dot_missing_root", "Device.WiFi.DataElements.Network.SSID", false, false, 1, 0, 6, 0, NULL, NULL, false},
 {"rej_trailing_space", P " ", false, false, 1, 0, 6, 0, NULL, NULL, false},
 {"rej_single_char", "a", false, false, 1, 0, 6, 0, NULL, NULL, false},
 {"rej_param_path", P "1.SSID", false, false, 1, 0, 6, 0, NULL, NULL, false},
 /* ---- CRASH cases on the original function (rejected after the fix) ---- */
 {"crash_empty_event_name", "", false, false, 1, 0, 6, 0, NULL, NULL, true},
 {"crash_null_event_name", NULL, false, false, 1, 0, 2, 0, NULL, NULL, true},
 {"crash_null_pdata", P, true, false, 1, 0, 2, 0, NULL, NULL, true},
 {"crash_no_data_model", P, false, true, 1, 0, 2, 0, NULL, NULL, true},
 {"crash_num_ssids_6", P, false, false, 6, 0, 0, -1, NULL, NULL, true},
 {"crash_num_ssids_100", P, false, false, 100, 0, 0, -1, NULL, NULL, true},

 { NULL, NULL, false, false, 0, 0, 0, 0, NULL, NULL, false }  /* sentinel */
};

static void fill(em_network_ssid_info_t *si, int i, int variant)
{
    memset(si, 0, sizeof(*si));
    snprintf(si->id, sizeof(si->id), "id%d", i);
    snprintf(si->ssid, sizeof(si->ssid), "net%d", i);
    snprintf(si->pass_phrase, sizeof(si->pass_phrase), "secret%d", i);
    si->num_bands = 2; snprintf(si->band[0], sizeof(si->band[0]), "2.4GHz"); snprintf(si->band[1], sizeof(si->band[1]), "5GHz");
    si->enable = true;
    si->num_akms = 2; snprintf(si->akm[0], sizeof(si->akm[0]), "psk"); snprintf(si->akm[1], sizeof(si->akm[1]), "sae");
    snprintf(si->suite_select, sizeof(si->suite_select), "00-0F-AC");
    si->advertisement = true;
    snprintf(si->mfp, sizeof(si->mfp), "required");
    memcpy(si->mobility_domain, "\xaa\xbb\xcc\xdd\xee\xff", 6);
    si->num_hauls = 2; si->haul_type[0] = em_haul_type_fronthaul; si->haul_type[1] = em_haul_type_backhaul;
    snprintf(si->auth_type, sizeof(si->auth_type), "sae");
    si->vlan_id = (unsigned short)(100 + i);
    if (variant == 1) { si->num_bands = 200; snprintf(si->band[2], sizeof(si->band[2]), "6GHz"); }
    if (variant == 2) { si->num_akms = 200; for (int k = 0; k < EM_MAX_AKMS; k++) snprintf(si->akm[k], sizeof(si->akm[k]), "k%d", k); }
    if (variant == 3) { si->num_hauls = 200; for (int k = 0; k < EM_MAX_HAUL_TYPES; k++) si->haul_type[k] = em_haul_type_fronthaul; }
    if (variant == 4) { si->num_hauls = 4; si->haul_type[2] = (em_haul_type_t)9; si->haul_type[3] = em_haul_type_iot; }
    if (variant == 5) { si->band[0][0] = '\0'; si->num_bands = 2; }
}

void construct_input(const test_case_t *tc)
{
    g_rec[0] = '\0'; g_ids = 0; g_nset = 0; g_dm = NULL;
    memset(name_store, 'N', sizeof(name_store));
    if (tc->event) snprintf(name_store + STI_LEFT, STI_NAME_SZ, "%s", tc->event);
    if (tc->no_dm) return;
    g_dm = (dm_easy_mesh_t *)calloc(1, sizeof(dm_easy_mesh_t));
    g_dm->m_num_net_ssids = (unsigned int)tc->nssid;
    for (int i = 0; i < tc->nssid && i < EM_MAX_NET_SSIDS; i++) fill(g_dm->m_network_ssid[i].get_network_ssid_info(), i, tc->variant);
}

void teardown(void) { free(g_dm); g_dm = NULL; }

} /* namespace sti */
