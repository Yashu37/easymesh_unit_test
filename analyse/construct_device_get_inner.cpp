/*
 * TEST CASES / CONSTRUCTOR: construct_device_get_inner
 *
 * event_name lives in name_store at offset DGI_LEFT (runner poisons the bytes in front of it and past
 * its NUL). One device 1 (or MAC alias 02:00:00:00:00:01): intf.mac 02:00:00:00:00:01, manufacturer
 * "Acme", serial "SN123", country "US", uptime 1000, 3 radios, security cap {1,2,3}, backhaul MAC
 * 02:00:00:00:00:09 whose parent device exists (dev_mac of the parent 02:00:00:00:00:77), media type 5.
 * Knobs (see test_case_t): n_down / n_down_fill backhaul-down MACs, n_policy / num_sta BTM steering
 * policy (MACs 02:00:00:00:01:<i>), ext (X_AIRTIES_*), no_dev, zero_intf_mac, no_sec, bh_zero, no_bh_dev.
 *
 * expect_rc: 0 success, 2 invalid_input, 25 invalid_namespace. Cases marked [spec] are wrong behaviour
 * (instance "1abc" read as 1 by atoi). The crash_* cases (method name shorter than the Network prefix,
 * path without a Device instance, num_backhaul_down_mac / num_sta above the 16-entry arrays) ABORT on
 * the original handler: they run last and UNFORKED (a plain make stops at the first ASan report);
 * FORK_CRASH=1 runs each in a forked child so all of them show.
 * Not tested (result is uninitialised stack data, so it is not deterministic): LocalSteeringDisallowedSTAList,
 * TrafficSeparationPolicy, SSIDtoVIDMapping and BTMSteeringDisallowedSTAList without a BTM policy return an
 * uninitialised 'rc' (the commented-out raw_data_set calls leave it unset).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "device_get_inner.h"

namespace dgi {

alignas(16) char name_store[DGI_LEFT + DGI_NAME_SZ + DGI_PAD];

#define N "Device.WiFi.DataElements.Network."
#define P(p) N "Device.1." p
/* {name, event, no_pdata, no_dm, no_dev, zero_intf, no_sec, bh_zero, no_bh_dev, n_down, n_down_fill, n_policy, num_sta, ext, rc, val, crash} */
#define OK(n, p, v) {n, P(p), false, false, false, false, false, false, false, 0, 0, 0, 0, 0, 0, v, false}
#define OKD(n, p, nd, nf, v) {n, P(p), false, false, false, false, false, false, false, nd, nf, 0, 0, 0, 0, v, false}
#define OKP(n, p, ns, v) {n, P(p), false, false, false, false, false, false, false, 0, 0, 1, ns, 0, 0, v, false}
#define OKE(n, p, e, v) {n, P(p), false, false, false, false, false, false, false, 0, 0, 0, 0, e, 0, v, false}
#define RJ(n, ev) {n, ev, false, false, false, false, false, false, false, 0, 0, 0, 0, 0, 2, NULL, false}
#define RJD(n, nd, nf) {n, P("BackhaulDownMACAddress"), false, false, false, false, false, false, false, nd, nf, 0, 0, 0, 0, NULL, false}
#define RJP(n, ns) {n, P("BTMSteeringDisallowedSTAList"), false, false, false, false, false, false, false, 0, 0, 1, ns, 0, 0, NULL, false}
#define RJC(n, ev) {n, ev, false, false, false, false, false, false, false, 0, 0, 0, 0, 0, 2, NULL, false}

test_case_t suite[] = {
 /* ---- plain parameters ---- */
 OK("ok_id", "ID", "02:00:00:00:00:01"),
 OK("ok_multiap_cap", "MultiAPCapabilities", "capX"),
 OK("ok_collection_interval", "CollectionInterval", "60"),
 OK("ok_max_reporting_rate", "MaxReportingRate", "7"),
 OK("ok_ap_metrics_interval", "APMetricsReportingInterval", "11"),
 OK("ok_manufacturer", "Manufacturer", "Acme"),
 OK("ok_serial", "SerialNumber", "SN123"),
 OK("ok_model", "ManufacturerModel", "M1"),
 OK("ok_software_ver", "SoftwareVersion", "v1.2"),
 OK("ok_country", "CountryCode", "US"),
 OK("ok_dfs", "DFSEnable", "1"),
 OK("ok_ctrl_mode", "ControllerOperationMode", "mode"),
 OK("ok_radio_entries", "RadioNumberOfEntries", "3"),
 OK("ok_uptime", "Uptime", "1000"),
 OK("ok_onboarding", "OnboardingProtocol", "1"),
 OK("ok_backhaul_mac", "BackhaulMACAddress", "02:00:00:00:00:09"),
 OK("ok_backhaul_alid", "BackhaulALID", "02:00:00:00:00:77"),
 OK("ok_backhaul_media_with_parent", "BackhaulMediaType", "32"),
 /* ---- backhaul-down list, BTM policy list, extended info ---- */
 OKD("ok_down_list_none", "BackhaulDownMACAddress", 0, 0, ""),
 OKD("ok_down_list_two", "BackhaulDownMACAddress", 2, 2, "02:00:00:00:02:00,02:00:00:00:02:01"),
 OKD("ok_down_list_16", "BackhaulDownMACAddress", 16, 16, NULL),
 OKD("ok_down_entries", "BackhaulDownNumberOfEntries", 5, 5, "5"),
 OKP("ok_btm_list_two", "BTMSteeringDisallowedSTAList", 2, "02:00:00:00:01:00,02:00:00:00:01:01"),
 OKP("ok_btm_list_16", "BTMSteeringDisallowedSTAList", 16, NULL),
 OKE("ok_bootid_not_received", "X_AIRTIES_BootID", 0, "0"),
 OKE("ok_bootid_received", "X_AIRTIES_BootID", 1, "99"),
 OKE("ok_clientid_empty", "X_AIRTIES_ClientID", 1, ""),
 OKE("ok_clientid_set", "X_AIRTIES_ClientID", 2, "cid"),
 OKE("ok_clientsecret_set", "X_AIRTIES_ClientSecret", 2, "csec"),
 {"ok_alias_path", N "Device.[02:00:00:00:00:01].Manufacturer", false, false, false, false, false, false, false, 0, 0, 0, 0, 0, 0, "Acme", false},
 {"ok_backhaul_mac_zero", P("BackhaulMACAddress"), false, false, false, false, false, true, false, 0, 0, 0, 0, 0, 0, "", false},
 {"ok_backhaul_alid_zero", P("BackhaulALID"), false, false, false, false, false, true, false, 0, 0, 0, 0, 0, 0, "", false},
 {"ok_backhaul_alid_no_parent", P("BackhaulALID"), false, false, false, false, false, false, true, 0, 0, 0, 0, 0, 0, "", false},
 {"ok_backhaul_media_zero_mac", P("BackhaulMediaType"), false, false, false, false, false, true, false, 0, 0, 0, 0, 0, 0, "5", false},
 /* ---- rejected ---- */
 RJ("rej_invalid_param", P("Foo")),
 RJ("rej_no_dot", "Manufacturer"),
 {"rej_device_not_found", N "Device.9.Manufacturer", false, false, false, false, false, false, false, 0, 0, 0, 0, 0, 25, NULL, false},
 {"rej_no_dm", P("Manufacturer"), false, true, false, false, false, false, false, 0, 0, 0, 0, 0, 25, NULL, false},
 {"rej_event_null", NULL, false, false, false, false, false, false, false, 0, 0, 0, 0, 0, 2, NULL, false},
 {"rej_pdata_null", P("Manufacturer"), true, false, false, false, false, false, false, 0, 0, 0, 0, 0, 2, NULL, false},
 {"rej_no_device_object", P("Manufacturer"), false, false, true, false, false, false, false, 0, 0, 0, 0, 0, 2, NULL, false},
 {"rej_zero_mac", P("Manufacturer"), false, false, false, true, false, false, false, 0, 0, 0, 0, 0, 2, NULL, false},
 {"rej_no_sec_cap", P("Manufacturer"), false, false, false, false, true, false, false, 0, 0, 0, 0, 0, 2, NULL, false},
 /* ---- [spec]: wrong behaviour, no abort ---- */
 RJ("rej_device_1abc [spec]", N "Device.1abc.Manufacturer"),
 /* ---- were CRASH cases on the original handler (now rejected rc 2, or the count is clamped to 16 and answered rc 0) ---- */
 RJC("rej_method_short", "X.ID"),
 RJC("rej_path_without_device", N "ID"),
 RJD("clamp_down_17", 17, 16),
 RJD("clamp_down_255", 255, 16),
 RJP("clamp_btm_17", 17),
 RJP("clamp_btm_255", 255),

 { NULL, NULL, false, false, false, false, false, false, false, 0, 0, 0, 0, 0, 0, NULL, false }  /* sentinel */
};

static dm_policy_t *g_pol = NULL;
static policy_map_t g_map;

void construct_input(const test_case_t *tc)
{
    memset(name_store, 0, sizeof(name_store));
    if (tc->event) snprintf(name_store + DGI_LEFT, DGI_NAME_SZ, "%s", tc->event);
    g_nset = 0; g_val[0] = '\0'; g_dm = NULL; g_bh = NULL; g_pol = NULL;
    if (tc->no_dm) return;
    dm_easy_mesh_t *dm = new dm_easy_mesh_t;
    memset((void *)dm, 0, sizeof(*dm));
    dm->no_dev = tc->no_dev; dm->nradios = 3; dm->has_sec = !tc->no_sec;
    dm->sec.onboarding_proto = 1; dm->sec.integrity_algo = 2; dm->sec.encryption_algo = 3;
    em_device_info_t *di = &dm->dev.info;
    unsigned char m1[6] = {2, 0, 0, 0, 0, 1}, m9[6] = {2, 0, 0, 0, 0, 9}, m77[6] = {2, 0, 0, 0, 0, 0x77};
    if (!tc->zero_intf_mac) memcpy(di->intf.mac, m1, 6);
    memcpy(di->id.dev_mac, m1, 6);
    snprintf(di->multi_ap_cap, sizeof(di->multi_ap_cap), "capX");
    snprintf(di->manufacturer, sizeof(di->manufacturer), "Acme");
    snprintf(di->serial_number, sizeof(di->serial_number), "SN123");
    snprintf(di->manufacturer_model, sizeof(di->manufacturer_model), "M1");
    snprintf(di->software_ver, sizeof(di->software_ver), "v1.2");
    snprintf(di->exec_env, sizeof(di->exec_env), "env");
    snprintf(di->dscp_map, sizeof(di->dscp_map), "dscp");
    snprintf(di->ctrl_operation_mode, sizeof(di->ctrl_operation_mode), "mode");
    snprintf(di->country_code, sizeof(di->country_code), "US");
    di->coll_interval = 60; di->report_unsuccess_assocs = true; di->max_reporting_rate = 7; di->ap_metrics_reporting_interval = 11;
    di->max_vids = 4; di->dfs_enable = true; di->uptime = 1000; di->cpu_temp = 45; di->backhaul_media_type = 5;
    if (!tc->bh_zero) memcpy(di->backhaul_mac.mac, m9, 6);
    di->num_backhaul_down_mac = tc->n_down;
    for (int i = 0; i < tc->n_down_fill && i < EM_BACKHAUL_DOWNMAC_ADDR; i++) snprintf(di->backhaul_down_mac[i], sizeof(di->backhaul_down_mac[i]), "02:00:00:00:02:%02x", i);
    if (tc->ext) {
        di->extended_info.received = true; di->extended_info.boot_id = 99;
        if (tc->ext == 2) { di->extended_info.client_id_len = 3; snprintf(di->extended_info.client_id, 64, "cid");
                            di->extended_info.client_secret_len = 4; snprintf(di->extended_info.client_secret, 64, "csec"); }
    }
    if (!tc->bh_zero && !tc->no_bh_dev) {
        g_bh = new dm_easy_mesh_t; memset((void *)g_bh, 0, sizeof(*g_bh));
        memcpy(g_bh->dev.info.intf.mac, m9, 6);        /* the lookup key (backhaul MAC) */
        memcpy(g_bh->dev.info.id.dev_mac, m77, 6);     /* ALID reported */
    }
    memset(&g_map, 0, sizeof(g_map));
    if (tc->n_policy) {
        g_pol = new dm_policy_t; memset((void *)g_pol, 0, sizeof(*g_pol));
        g_pol->m_policy.id.type = em_policy_id_type_steering_btm;
        g_pol->m_policy.num_sta = tc->num_sta;
        for (int i = 0; i < EM_MAX_STA_PER_STEER_POLICY; i++) { unsigned char m[6] = {2, 0, 0, 0, 1, (unsigned char)i}; memcpy(g_pol->m_policy.sta_mac[i], m, 6); }
        g_map.p[0] = g_pol; g_map.n = 1;
        dm->m_policy_map = &g_map;
    } else dm->m_policy_map = NULL;
    g_dm = dm;
}

void teardown(void)
{
    delete g_pol; g_pol = NULL;
    delete g_bh; g_bh = NULL;
    delete g_dm; g_dm = NULL;
}

} /* namespace dgi */
