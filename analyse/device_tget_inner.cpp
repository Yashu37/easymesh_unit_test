/*
 * HANDLER: device_tget_inner
 *
 * Function copied VERBATIM from unified-wifi-mesh src/ctrl/dm_easy_mesh_ctrl.cpp
 * (develop @ 1ba9529), dm_easy_mesh_ctrl_t::device_tget_inner, with fill_comma_sep()
 * (same file) and dm_easy_mesh_t::maclist_to_string() (src/dm/dm_easy_mesh.cpp), both verbatim.
 * Local arrays: path[512], val_str[MAX_EM_BUFF_SZ=1024], maclist_str[256],
 * maclist[14], tmp (vector of em_short_string_t[64]).
 * Scaffolding: a list of data models (dm_spec_t in the test case) with only the fields the
 * handler reads; property_append_tail records "idx:name=value"; radio / APMLD sub-handlers
 * are not under test (they are separate functions) and only record their path.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cstring>
#include <stdint.h>
#include <string>
#include <vector>
#include <type_traits>
#include "device_tget_inner.h"

namespace dti {

/* --- scaffolding: data models --- */
char g_rec[16384];
int g_raw_set = 0;
int g_ndev = 0;
static bus_data_prop_t g_dummy_prop;
static void rec(unsigned int idx, const char *name, const char *val)
{
    size_t l = strlen(g_rec);
    snprintf(g_rec + l, sizeof(g_rec) - l, "%u:%s=%s\n", idx, name, val);
    if (!strcmp(name, "ID")) g_ndev++;
}
dm_easy_mesh_t *g_dm[DTI_MAXDM + 1];

int g_ndm = 0;

class dm_easy_mesh_ctrl_t {
public:
    dm_easy_mesh_t *get_first_dm() { return g_ndm ? g_dm[0] : NULL; }
    dm_easy_mesh_t *get_next_dm(dm_easy_mesh_t *dm)
    { for (int i = 0; i < g_ndm; i++) if (g_dm[i] == dm) return (i + 1 < g_ndm) ? g_dm[i + 1] : NULL; return NULL; }
    dm_device_t *get_dm_dev(unsigned char *dev_mac, unsigned char *bmac)
    {   (void)dev_mac;
        for (int i = 0; i < g_ndm; i++) if (g_dm[i]->get_device() && !memcmp(g_dm[i]->dev.info.id.dev_mac, bmac, 6)) return &g_dm[i]->dev;
        return NULL;
    }
    void fill_comma_sep(em_short_string_t str[], size_t max, char *buf);
    bus_error_t device_tget_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    void radio_tget_params(dm_easy_mesh_t *dm, const char *path, bus_data_prop_t **prop) { (void)dm; (void)prop; rec(0, "radio_path", path); }
    void apmld_tget_params(dm_easy_mesh_t *dm, const char *path, bus_data_prop_t **prop) { (void)dm; (void)prop; rec(0, "apmld_path", path); }
    void raw_data_set(raw_data_t *p, bus_data_prop_t *prop) { (void)p; (void)prop; g_raw_set++; }
    void property_append_tail(bus_data_prop_t **prop, const char *root, unsigned int idx, const char *name, const char *v)
    { (void)root; if (!*prop) *prop = &g_dummy_prop; rec(idx, name, v ? v : "(null)"); }
    void property_append_tail(bus_data_prop_t **prop, const char *root, unsigned int idx, const char *name, const unsigned char *mac)
    { char s[18]; (void)root; if (!*prop) *prop = &g_dummy_prop; dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *>(mac), s); rec(idx, name, s); }
    template <typename T>
    typename std::enable_if<std::is_arithmetic<T>::value || std::is_enum<T>::value>::type
    property_append_tail(bus_data_prop_t **prop, const char *root, unsigned int idx, const char *name, T v)
    { char s[32]; (void)root; if (!*prop) *prop = &g_dummy_prop; snprintf(s, sizeof(s), "%lld", (long long)v); rec(idx, name, s); }
};
class em_ctrl_t {
public:
    dm_easy_mesh_ctrl_t m_data_model;
    static em_ctrl_t *get_em_ctrl_instance();
    dm_easy_mesh_ctrl_t *get_dm_ctrl() { return &m_data_model; }
};
static em_ctrl_t g_ctrl;
em_ctrl_t *em_ctrl_t::get_em_ctrl_instance() { return &g_ctrl; }

/* --- copied verbatim from src/dm/dm_easy_mesh.cpp --- */
void dm_easy_mesh_t::maclist_to_string(mac_address_t mac_list[], size_t mac_count, char *string, uint16_t str_len)
{
    uint8_t idx = 0;

    if (mac_list == NULL) {
        return;
    }

    while (str_len >= sizeof(mac_addr_str_t) && idx < mac_count) {
        dm_easy_mesh_t::macbytes_to_string(mac_list[idx], string);
        string += (sizeof(mac_addr_str_t) - 1);
        str_len -= sizeof(mac_addr_str_t);
        if (++idx >= mac_count || str_len == 0) {
            break;
        }
        *string = ',';
        ++string;
    }
}

/* --- copied verbatim from src/ctrl/dm_easy_mesh_ctrl.cpp --- */
void dm_easy_mesh_ctrl_t::fill_comma_sep(em_short_string_t str[], size_t max, char *buf)
{
    unsigned int cnt = 0;
    const char *delim = NULL;

    if (max > 15) {
        max = 15;
    }

    while (cnt < max) {
        if (strlen(str[cnt]) > 0) {
            if (delim) {
                strcat(buf, delim);
            } else {
                delim = ",";
            }
            strcat(buf, str[cnt]);
        } else {
            break;
        }
        cnt++;
    }
}

bus_error_t dm_easy_mesh_ctrl_t::device_tget_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    (void) user_data;
    const char *root = event_name;
    char path[512] = { 0 };
    char val_str[MAX_EM_BUFF_SZ] = { 0 };
    bus_data_prop_t *property = NULL;
    bus_error_t rc = bus_error_success;

    if (!event_name || !p_data) {
        return bus_error_invalid_input;
    }
    if (*(event_name + (strlen(event_name) - 1)) != '.') {
        /* Only partial paths are valid */
        return bus_error_invalid_operation;
    }

    dm_easy_mesh_ctrl_t *dm_ctrl = em_ctrl_t::get_em_ctrl_instance()->get_dm_ctrl();
    dm_easy_mesh_t *dm = dm_ctrl->get_first_dm();
    if (dm == NULL) {
        em_printfout("data model is NULL\n");
        return bus_error_invalid_input;
    }

    /* Calculate device count */
    unsigned int device_cnt = 0;
    int max_id = 0;
    while (dm != NULL) {
        if (dm->is_controller()) {
            dm = dm_ctrl->get_next_dm(dm);
            continue;
        }
        if (dm->get_id() < 0) {
            dm = dm_ctrl->get_next_dm(dm);
            continue;
        }
        dm_device_t *dev = dm->get_device();
        if (dev == NULL) {
            dm = dm_ctrl->get_next_dm(dm);
            continue;
        }
        em_device_info_t *di = dev->get_device_info();
        if (memcmp(di->id.dev_mac, ZERO_MAC_ADDR, sizeof(di->id.dev_mac)) == 0) {
            dm = dm_ctrl->get_next_dm(dm);
            continue;
        }
        if (dm->get_id() > max_id) {
            max_id = dm->get_id();
        }
        ++device_cnt;
        dm = dm_ctrl->get_next_dm(dm);
    }

    /* Iterate according to dm id */
    for (unsigned int idx = 1, cnt = 0; cnt < device_cnt && idx <= static_cast<unsigned int>(max_id); idx++) {
        dm = dm_ctrl->get_first_dm();
        do {
            if (dm && (dm->get_id() == static_cast<int>(idx))) {
                break;
            }
            dm = dm_ctrl->get_next_dm(dm);
        } while (dm != NULL);
        if (dm == NULL) {
            continue;
        }

	if (dm->is_controller()) {
            continue;
        }

        dm_device_t *dev = dm->get_device();
        if (dev == NULL) {
            continue;
        }

        em_device_info_t *di = dev->get_device_info();
        if (memcmp(di->id.dev_mac, ZERO_MAC_ADDR, sizeof(di->id.dev_mac)) == 0) {
            continue;
        }
        ++cnt;

        em_ieee_1905_security_cap_t *sec_cap = dm->get_ieee_1905_security_cap();

        dm_ctrl->property_append_tail(&property, root, idx, "ID", di->id.dev_mac);
        dm_ctrl->property_append_tail(&property, root, idx, "Manufacturer", di->manufacturer);
        dm_ctrl->property_append_tail(&property, root, idx, "SerialNumber", di->serial_number);
        dm_ctrl->property_append_tail(&property, root, idx, "ManufacturerModel", di->manufacturer_model);
        dm_ctrl->property_append_tail(&property, root, idx, "SoftwareVersion", di->software_ver);
        dm_ctrl->property_append_tail(&property, root, idx, "ExecutionEnv", di->exec_env);
        dm_ctrl->property_append_tail(&property, root, idx, "CountryCode", di->country_code);
        if (memcmp(di->backhaul_mac.mac, ZERO_MAC_ADDR, sizeof(ZERO_MAC_ADDR)) == 0) {
            dm_ctrl->property_append_tail(&property, root, idx, "BackhaulMACAddress", "");
        } else {
            dm_ctrl->property_append_tail(&property, root, idx, "BackhaulMACAddress", di->backhaul_mac.mac);
        }
        const size_t n = static_cast<size_t>(di->num_backhaul_down_mac);
        std::vector<em_short_string_t> tmp(n);

        for (size_t i = 0; i < n; i++) {
            std::strncpy(tmp[i], di->backhaul_down_mac[i], sizeof(tmp[i]) - 1);
            tmp[i][sizeof(tmp[i]) - 1] = '\0';
        }
        dm_ctrl->fill_comma_sep(tmp.data(), n, val_str);
        dm_ctrl->property_append_tail(&property, root, idx, "BackhaulDownMACAddress", val_str);
        if (memcmp(di->backhaul_mac.mac, ZERO_MAC_ADDR, sizeof(ZERO_MAC_ADDR)) == 0) {
            dm_ctrl->property_append_tail(&property, root, idx, "BackhaulALID", "");
        } else {
            dm_device_t *bhdev = dm_ctrl->get_dm_dev(di->id.dev_mac, di->backhaul_mac.mac);
            if (bhdev == NULL) {
                dm_ctrl->property_append_tail(&property, root, idx, "BackhaulALID", "");
            } else {
                em_device_info_t *bhdi = bhdev->get_device_info();
                dm_ctrl->property_append_tail(&property, root, idx, "BackhaulALID", bhdi->id.dev_mac);
            }
        }
        if (memcmp(di->backhaul_mac.mac, ZERO_MAC_ADDR, sizeof(ZERO_MAC_ADDR)) == 0) {
            dm_ctrl->property_append_tail(&property, root, idx, "BackhaulMediaType", di->backhaul_media_type);
        } else {
            dm_ctrl->property_append_tail(&property, root, idx, "BackhaulMediaType", WIFI_80211_VARIANT_AC);
        }
        dm_ctrl->property_append_tail(&property, root, idx, "RadioNumberOfEntries", dm->get_num_radios());
        dm_ctrl->property_append_tail(&property, root, idx, "CACStatusNumberOfEntries", 0U);
        dm_ctrl->property_append_tail(&property, root, idx, "BackhaulDownNumberOfEntries", di->num_backhaul_down_mac);
        dm_ctrl->property_append_tail(&property, root, idx, "OnboardingProtocol", sec_cap ? sec_cap->onboarding_proto : 0);
        dm_ctrl->property_append_tail(&property, root, idx, "IntegrityAlgorithm", sec_cap ? sec_cap->integrity_algo : 0);
        dm_ctrl->property_append_tail(&property, root, idx, "EncryptionAlgorithm", sec_cap ? sec_cap->encryption_algo : 0);
        dm_ctrl->property_append_tail(&property, root, idx, "X_AIRTIES_DeviceInfo.Uptime", di->uptime);
        dm_ctrl->property_append_tail(&property, root, idx, "X_AIRTIES_DeviceInfo.MemoryStatus.Total", di->total_mem);
        dm_ctrl->property_append_tail(&property, root, idx, "X_AIRTIES_DeviceInfo.MemoryStatus.Free", di->free_mem);
        dm_ctrl->property_append_tail(&property, root, idx, "X_AIRTIES_DeviceInfo.MemoryStatus.Cached", di->cached_mem);
        dm_ctrl->property_append_tail(&property, root, idx, "X_AIRTIES_DeviceInfo.ProcessStatus.CPUUsage", di->cpu_load);
        dm_ctrl->property_append_tail(&property, root, idx, "X_AIRTIES_DeviceInfo.ProcessStatus.CPUTemperature", di->cpu_temp);

        em_ext_device_info_t *edi = &di->extended_info;
        dm_ctrl->property_append_tail(&property, root, idx, "X_AIRTIES_BootID", edi->received ? edi->boot_id : 0);
        if (edi->received && edi->client_id_len) {
            dm_ctrl->property_append_tail(&property, root, idx, "X_AIRTIES_ClientID", edi->client_id);
        } else {
            dm_ctrl->property_append_tail(&property, root, idx, "X_AIRTIES_ClientID", "");
        }
        if (edi->received && edi->client_secret_len) {
            dm_ctrl->property_append_tail(&property, root, idx, "X_AIRTIES_ClientSecret", edi->client_secret);
        } else {
            dm_ctrl->property_append_tail(&property, root, idx, "X_AIRTIES_ClientSecret", "");
        }

        snprintf(path, sizeof(path) - 1, "%s%d.Radio.", root, idx);
        dm_ctrl->radio_tget_params(dm, path, &property);

        snprintf(path, sizeof(path) - 1, "%s%d.APMLD.", root, idx);
        dm_ctrl->apmld_tget_params(dm, path, &property);

        if (dm->is_bsta_mld_present()) {
            char maclist_str[MAX_MACLIST_STRLEN] = { 0 };
            mac_address_t maclist[MAX_MACLIST_ITEMS];
            em_bsta_mld_info_t &bsmi = dm->get_bsta_mld_info();
            dm_ctrl->property_append_tail(&property, root, idx, "bSTAMLD.MLDMACAddress", bsmi.mac_addr_valid ? bsmi.mac_addr : ZERO_MAC_ADDR);
            dm_ctrl->property_append_tail(&property, root, idx, "bSTAMLD.BSSID", bsmi.ap_mld_mac_addr_valid ? bsmi.ap_mld_mac_addr : ZERO_MAC_ADDR);
            if (bsmi.num_affiliated_bsta) {
                for (unsigned int i = 0; i < bsmi.num_affiliated_bsta && i < MAX_MACLIST_ITEMS; i++) {
                    memcpy(maclist[i], bsmi.affiliated_bsta[i].mac_addr, sizeof(mac_address_t));
                }
                dm_easy_mesh_t::maclist_to_string(maclist, bsmi.num_affiliated_bsta, maclist_str, sizeof(maclist_str));
            }
            dm_ctrl->property_append_tail(&property, root, idx, "bSTAMLD.AffiliatedbSTAList", maclist_str);
            dm_ctrl->property_append_tail(&property, root, idx, "bSTAMLD.bSTAMLDConfig.EMLMREnabled", bsmi.emlmr);
            dm_ctrl->property_append_tail(&property, root, idx, "bSTAMLD.bSTAMLDConfig.EMLSREnabled", bsmi.emlsr);
            dm_ctrl->property_append_tail(&property, root, idx, "bSTAMLD.bSTAMLDConfig.STREnabled", bsmi.str);
            dm_ctrl->property_append_tail(&property, root, idx, "bSTAMLD.bSTAMLDConfig.NSTREnabled", bsmi.nstr);
        }
    }

    if (property) {
        dm_ctrl->raw_data_set(p_data, property);
    }

    return rc;
}

int invoke(const char *event, bool no_pdata)
{
    raw_data_t raw;
    memset(&raw, 0, sizeof(raw));
    bus_user_data_t ud;
    return (int)g_ctrl.m_data_model.device_tget_inner((char *)event, no_pdata ? NULL : &raw, &ud);
}

} /* namespace dti */
