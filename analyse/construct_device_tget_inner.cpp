/*
 * TEST CASES / CONSTRUCTOR: construct_device_tget_inner
 *
 * event_name lives in name_store at offset DTI_LEFT (runner poisons the bytes in front of it and
 * past its NUL). Each case lists up to 8 data models (dm_spec_t); they are heap allocated one by
 * one so ASan redzones sit between them. Device MAC = 02:00:00:00:00:<mac>, backhaul-down entry k
 * of device N = 02:00:00:00:<N>:<k> (17 chars), affiliated bSTA k = 02:00:00:00:00:<k>.
 * property_append_tail records "idx:name=value" lines; the checks look for `has` / `not_has`.
 *
 * expect_rc: 0 success, 2 invalid_input, 6 invalid_operation (stand-in values). Cases marked [spec] are
 * wrong behaviour (no abort). The crash_* cases ABORT on the original handler: the runner executes
 * them last and UNFORKED (a plain make shows the ASan report and stops); FORK_CRASH=1 runs each
 * in a forked child so all of them show.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "device_tget_inner.h"

namespace dti {

alignas(16) char name_store[DTI_LEFT + DTI_NAME_SZ + DTI_PAD];

#define P "Device.WiFi.DataElements.Network.Device."
#define EV_LONG ((const char *)1)
#define E0 {0}
/* in declaration order: id, controller, no_device, mac, bh_mac, n_down, n_down_fill, full_down, ext_received, has_sec, bsta_mld, n_aff */
#define DV(i, m) {i, false, false, m, 0, 0, 0, false, false, false, false, 0}
#define DVD(i, m, nd, nf) {i, false, false, m, 0, nd, nf, false, false, false, false, 0}
#define OK(n, devs, hs, nh, ...) {n, P, false, {__VA_ARGS__}, 0, devs, hs, nh, false}
#define CR(n, devs, ...) {n, P, false, {__VA_ARGS__}, 0, devs, NULL, NULL, true}

test_case_t suite[] = {
 /* ---- device selection ---- */
 OK("ok_one_device", 1, "1:ID=02:00:00:00:00:01\n", NULL, DV(1, 1)),
 OK("ok_fields", 1, "1:Manufacturer=Acme\n", NULL, DV(1, 1)),
 OK("ok_two_devices", 2, "2:ID=02:00:00:00:00:02\n", NULL, DV(1, 1), DV(2, 2)),
 OK("ok_controller_skipped", 1, "2:ID=02:00:00:00:00:02\n", "1:ID=", {1, true, false, 1, 0, 0, 0, false, false, false, false, 0}, DV(2, 2)),
 OK("ok_zero_mac_skipped", 1, "2:ID=02:00:00:00:00:02\n", "1:ID=", DV(1, 0), DV(2, 2)),
 OK("ok_no_device_skipped", 1, "2:ID=02:00:00:00:00:02\n", "1:ID=", {1, false, true, 1, 0, 0, 0, false, false, false, false, 0}, DV(2, 2)),
 OK("ok_negative_id_skipped", 1, "1:ID=02:00:00:00:00:01\n", NULL, DV(-1, 5), DV(1, 1)),
 OK("ok_id_gap", 2, "3:ID=02:00:00:00:00:03\n", NULL, DV(1, 1), DV(3, 3)),
 OK("ok_id_zero_not_reported", 1, "1:ID=02:00:00:00:00:01\n", "0:ID=", DV(0, 9), DV(1, 1)),
 {"ok_no_dm", P, false, {E0}, 2, -1, NULL, NULL, false},
 OK("ok_all_controllers", 0, NULL, NULL, {1, true, false, 1, 0, 0, 0, false, false, false, false, 0}),
 /* ---- backhaul ---- */
 OK("ok_backhaul_down_3", 1, "1:BackhaulDownMACAddress=02:00:00:00:01:00,02:00:00:00:01:01,02:00:00:00:01:02\n", NULL, DVD(1, 1, 3, 3)),
 OK("ok_backhaul_down_count_entries", 1, "1:BackhaulDownNumberOfEntries=3\n", NULL, DVD(1, 1, 3, 3)),
 OK("ok_backhaul_down_0", 1, "1:BackhaulDownMACAddress=\n", NULL, DVD(1, 1, 0, 0)),
 OK("ok_backhaul_down_16_capped_15", 1, "02:00:00:00:01:0e\n", "02:00:00:00:01:0f", DVD(1, 1, 16, 16)),
 OK("ok_backhaul_zero_mac", 1, "1:BackhaulMACAddress=\n", NULL, DV(1, 1)),
 OK("ok_backhaul_alid_found", 2, "1:BackhaulALID=02:00:00:00:00:02\n", NULL, {1, false, false, 1, 2, 0, 0, false, false, false, false, 0}, DV(2, 2)),
 OK("ok_backhaul_media_type_ac", 1, "1:BackhaulMediaType=32\n", NULL, {1, false, false, 1, 9, 0, 0, false, false, false, false, 0}),
 OK("ok_backhaul_alid_missing", 1, "1:BackhaulALID=\n", NULL, {1, false, false, 1, 9, 0, 0, false, false, false, false, 0}),
 /* ---- extended info / security / bSTA MLD ---- */
 OK("ok_ext_received", 1, "1:X_AIRTIES_ClientID=cid\n", NULL, {1, false, false, 1, 0, 0, 0, false, true, false, false, 0}),
 OK("ok_ext_boot_id", 1, "1:X_AIRTIES_BootID=7\n", NULL, {1, false, false, 1, 0, 0, 0, false, true, false, false, 0}),
 OK("ok_ext_not_received", 1, "1:X_AIRTIES_BootID=0\n", "cid", DV(1, 1)),
 OK("ok_sec_cap", 1, "1:OnboardingProtocol=1\n", NULL, {1, false, false, 1, 0, 0, 0, false, false, true, false, 0}),
 OK("ok_no_sec_cap", 1, "1:OnboardingProtocol=0\n", NULL, DV(1, 1)),
 OK("ok_bsta_mld_3", 1, "1:bSTAMLD.AffiliatedbSTAList=02:00:00:00:00:00,02:00:00:00:00:01,02:00:00:00:00:02\n", NULL, {1, false, false, 1, 0, 0, 0, false, false, false, true, 3}),
 OK("ok_bsta_mld_14", 1, ",02:00:00:00:00:0d\n", NULL, {1, false, false, 1, 0, 0, 0, false, false, false, true, 14}),
 OK("ok_bsta_mld_20_list_capped [spec]", 1, "02:00:00:00:00:0d\n", ",02:00:00:00:00:0e", {1, false, false, 1, 0, 0, 0, false, false, false, true, 20}),
 OK("ok_bsta_mld_absent", 1, "1:ID=", "bSTAMLD", DV(1, 1)),
 /* ---- event name ---- */
 {"ok_event_dot_only", ".", false, {DV(1, 1), E0}, 0, 1, NULL, NULL, false},
 {"ok_event_long_599", EV_LONG, false, {DV(1, 1), E0}, 0, 1, "1:ID=", NULL, false},
 {"rej_event_null", NULL, false, {DV(1, 1), E0}, 2, -1, NULL, NULL, false},
 {"rej_pdata_null", P, true, {DV(1, 1), E0}, 2, -1, NULL, NULL, false},
 {"rej_no_trailing_dot", "Device.WiFi.DataElements.Network.Device", false, {DV(1, 1), E0}, 6, -1, NULL, NULL, false},
 {"rej_single_char_no_dot", "x", false, {DV(1, 1), E0}, 6, -1, NULL, NULL, false},
 /* ---- [spec]: wrong behaviour, no abort ---- */
 OK("ok_down_list_not_stale_second_device [spec]", 2, "2:BackhaulDownMACAddress=02:00:00:00:02:00,02:00:00:00:02:01\n", NULL, DVD(1, 1, 2, 2), DVD(2, 2, 2, 2)),
 /* ---- CRASH cases (run last, unforked) ---- */
 {"crash_event_name_empty", "", false, {DV(1, 1), E0}, 6, -1, NULL, NULL, true},
 CR("crash_down_count_17", 1, DVD(1, 1, 17, 16)),
 CR("crash_down_count_255", 1, DVD(1, 1, 255, 16)),
 CR("crash_val_str_overflow_5_devices", 5, DVD(1, 1, 15, 15), DVD(2, 2, 15, 15), DVD(3, 3, 15, 15), DVD(4, 4, 15, 15), DVD(5, 5, 15, 15)),

 { NULL, NULL, false, {E0}, 0, 0, NULL, NULL, false }  /* sentinel */
};

static void build_dms(const test_case_t *tc)
{
    g_ndm = 0;
    for (int i = 0; i < DTI_MAXDM; i++) {
        const dm_spec_t *s = &tc->dms[i];
        /* an all-zero spec is the end marker; id 0 is allowed when any other field is set */
        if (!s->id && !s->mac && !s->controller && !s->no_device && !s->bh_mac && !s->n_down) break;
        dm_easy_mesh_t *dm = new dm_easy_mesh_t;
        memset((void *)dm, 0, sizeof(*dm));
        dm->id = s->id; dm->ctrl = s->controller; dm->no_dev = s->no_device; dm->nradios = 2;
        em_device_info_t *di = &dm->dev.info;
        if (s->mac) { unsigned char m[6] = {2, 0, 0, 0, 0, s->mac}; memcpy(di->id.dev_mac, m, 6); }
        if (s->bh_mac) { unsigned char m[6] = {2, 0, 0, 0, 0, s->bh_mac}; memcpy(di->backhaul_mac.mac, m, 6); }
        snprintf(di->manufacturer, sizeof(di->manufacturer), "Acme");
        snprintf(di->serial_number, sizeof(di->serial_number), "SN%d", i);
        snprintf(di->manufacturer_model, sizeof(di->manufacturer_model), "M1");
        snprintf(di->software_ver, sizeof(di->software_ver), "1.0");
        snprintf(di->exec_env, sizeof(di->exec_env), "linux");
        snprintf(di->country_code, sizeof(di->country_code), "US");
        di->num_backhaul_down_mac = (unsigned char)s->n_down;
        for (int k = 0; k < s->n_down_fill && k < EM_BACKHAUL_DOWNMAC_ADDR; k++)
            snprintf(di->backhaul_down_mac[k], sizeof(di->backhaul_down_mac[k]), "02:00:00:00:%02x:%02x", i + 1, k);
        di->extended_info.received = s->ext_received;
        if (s->ext_received) {
            di->extended_info.boot_id = 7;
            di->extended_info.client_id_len = 3; snprintf(di->extended_info.client_id, 256, "cid");
            di->extended_info.client_secret_len = 3; snprintf(di->extended_info.client_secret, 256, "sec");
        }
        dm->has_sec = s->has_sec;
        if (s->has_sec) { dm->sec.onboarding_proto = 1; dm->sec.integrity_algo = 2; dm->sec.encryption_algo = 3; }
        dm->bsta = s->bsta_mld;
        if (s->bsta_mld) {
            dm->bsm.num_affiliated_bsta = (unsigned char)s->n_aff;
            for (int k = 0; k < s->n_aff && k < 64; k++) { unsigned char m[6] = {2, 0, 0, 0, 0, (unsigned char)k}; memcpy(dm->bsm.affiliated_bsta[k].mac_addr, m, 6); }
        }
        g_dm[g_ndm++] = dm;
    }
}

void construct_input(const test_case_t *tc)
{
    memset(name_store, 0, sizeof(name_store));
    if (tc->event == EV_LONG) { memset(name_store + DTI_LEFT, 'a', 598); name_store[DTI_LEFT + 598] = '.'; }
    else if (tc->event) snprintf(name_store + DTI_LEFT, DTI_NAME_SZ, "%s", tc->event);
    g_rec[0] = '\0'; g_raw_set = 0; g_ndev = 0;
    build_dms(tc);
}

void teardown(void)
{
    for (int i = 0; i < g_ndm; i++) { delete g_dm[i]; g_dm[i] = NULL; }
    g_ndm = 0;
}

} /* namespace dti */
