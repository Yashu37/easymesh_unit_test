/*
 * HANDLER: bss_tget_params
 *
 * Function copied (fix 1 applied, start fix n / end fix n markers) from unified-wifi-mesh src/ctrl/dm_easy_mesh_ctrl.cpp
 * (develop @ 1ba9529), dm_easy_mesh_ctrl_t::bss_tget_params. Local arrays: path[512], val_str[1024]
 * (written by the AKM helper) and the loop over dm->get_num_bss() with dm->get_bss(i) = &m_bss[i]
 * (m_bss[EM_MAX_BSSS = 24]; get_num_bss() returns the raw m_num_bss).
 * Scaffolding: one data model with a BSS list described by btp::bss_spec_t; property_append_tail records
 * "idx:name=value"; fill_bss_akms_allowed (own function: AKM list from the profile) is a stub that writes
 * "psk" for the BSS's own haul side and "" for the other; sta_tget_params only records its path.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <string>
#include <type_traits>
#include "bss_tget_params.h"

namespace btp {

char g_rec[65536];
int g_rows = 0;
dm_easy_mesh_t *g_dm = NULL;
static bus_data_prop_t g_dummy_prop;
static void rec(unsigned int idx, const char *name, const char *val)
{
    size_t l = strlen(g_rec);
    if (l + 512 > sizeof(g_rec)) return;
    snprintf(g_rec + l, sizeof(g_rec) - l, "%u:%.200s=%.200s\n", idx, name, val);
    if (!strcmp(name, "BSSID")) g_rows++;
}

class dm_easy_mesh_ctrl_t {
public:
    void fill_bss_akms_allowed(dm_easy_mesh_t *dm, em_bss_info_t *bi, bool backhaul, char *buf, size_t buf_len)
    { (void)dm; buf[0] = '\0'; if (backhaul == (bi->id.haul_type == em_haul_type_backhaul)) snprintf(buf, buf_len, "psk"); }
    void sta_tget_params(dm_easy_mesh_t *dm, const char *path, em_bss_info_t *bi, bus_data_prop_t **prop) { (void)dm; (void)bi; (void)prop; rec(0, "sta_path", path); }
    void property_append_tail(bus_data_prop_t **prop, const char *root, unsigned int idx, const char *name, const char *v)
    { (void)root; if (!*prop) *prop = &g_dummy_prop; rec(idx, name, v ? v : "(null)"); }
    void property_append_tail(bus_data_prop_t **prop, const char *root, unsigned int idx, const char *name, const unsigned char *mac)
    { char s[18]; (void)root; if (!*prop) *prop = &g_dummy_prop; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); rec(idx, name, s); }
    template <typename T>
    typename std::enable_if<std::is_arithmetic<T>::value || std::is_enum<T>::value>::type
    property_append_tail(bus_data_prop_t **prop, const char *root, unsigned int idx, const char *name, T v)
    { char s[32]; (void)root; if (!*prop) *prop = &g_dummy_prop; snprintf(s, sizeof(s), "%lld", (long long)v); rec(idx, name, s); }
    bus_error_t bss_tget_params(dm_easy_mesh_t *dm, const char *root, em_radio_info_t *ri, bus_data_prop_t **property);
};
class em_ctrl_t {
public:
    dm_easy_mesh_ctrl_t m_data_model;
    static em_ctrl_t *get_em_ctrl_instance();
    dm_easy_mesh_ctrl_t *get_dm_ctrl() { return &m_data_model; }
};
static em_ctrl_t g_ctrl;
em_ctrl_t *em_ctrl_t::get_em_ctrl_instance() { return &g_ctrl; }

/* --- copied verbatim from src/ctrl/dm_easy_mesh_ctrl.cpp --- */
bus_error_t dm_easy_mesh_ctrl_t::bss_tget_params(dm_easy_mesh_t *dm, const char *root, em_radio_info_t *ri, bus_data_prop_t **property)
{
    char path[512];
    char val_str[MAX_EM_BUFF_SZ] = { 0 };
    bus_error_t rc = bus_error_success;

    dm_easy_mesh_ctrl_t *dm_ctrl = em_ctrl_t::get_em_ctrl_instance()->get_dm_ctrl();
    unsigned int idx = 0;
/* start fix 1 */
    unsigned int num_bss = dm->get_num_bss();
    if (num_bss > EM_MAX_BSSS) {
        num_bss = EM_MAX_BSSS;
    }
/* end fix 1 */
    for (unsigned int i = 0; i < num_bss; i++) {
        dm_bss_t *bss = dm->get_bss(i);
        if (bss == NULL) {
            continue;
        }
        em_bss_info_t *bi = bss->get_bss_info();
        /* bss_get_inner(), sta_get_inner(), sta_tget_inner() and get_dm_bss() number the rows the same way. */
        if (memcmp(bi->bssid.mac, ZERO_MAC_ADDR, sizeof(ZERO_MAC_ADDR)) == 0 ||
            memcmp(ri->id.ruid, bi->ruid.mac, sizeof(bi->ruid.mac)) != 0) {
            continue;
        }
        ++idx;

        dm_ctrl->property_append_tail(property, root, idx, "BSSID", bi->bssid.mac);
        dm_ctrl->property_append_tail(property, root, idx, "SSID", bi->ssid);
        dm_ctrl->property_append_tail(property, root, idx, "Enabled", bi->enabled);
        dm_ctrl->property_append_tail(property, root, idx, "ByteCounterUnits", bi->byte_counter_units);
        dm_ctrl->property_append_tail(property, root, idx, "BackhaulUse", (bi->id.haul_type == em_haul_type_backhaul));
        dm_ctrl->property_append_tail(property, root, idx, "FronthaulUse", (bi->id.haul_type == em_haul_type_fronthaul));
        memset(val_str, 0, sizeof(val_str));
        dm_ctrl->fill_bss_akms_allowed(dm, bi, false, val_str, sizeof(val_str));
        dm_ctrl->property_append_tail(property, root, idx, "FronthaulAKMsAllowed", val_str);
        dm_ctrl->property_append_tail(property, root, idx, "FronthaulSuiteSelector", 0U);
        memset(val_str, 0, sizeof(val_str));
        dm_ctrl->fill_bss_akms_allowed(dm, bi, true, val_str, sizeof(val_str));
        dm_ctrl->property_append_tail(property, root, idx, "BackhaulAKMsAllowed", val_str);
        dm_ctrl->property_append_tail(property, root, idx, "BackhaulSuiteSelector", 0U);
        dm_ctrl->property_append_tail(property, root, idx, "STANumberOfEntries", bi->numberofsta);

        snprintf(path, sizeof(path) - 1, "%s%d.STA.", root, idx);
        dm_ctrl->sta_tget_params(dm, path, bi, property);
    }

    return rc;
}

int invoke(const char *root, int ri_radio)
{
    bus_data_prop_t *prop = NULL;
    em_radio_info_t ri;
    memset(&ri, 0, sizeof(ri));
    unsigned char m[6] = {2, 0, 0, 0, 0, (unsigned char)ri_radio};
    memcpy(ri.id.ruid, m, 6);
    return (int)g_ctrl.m_data_model.bss_tget_params(g_dm, root, &ri, &prop);
}

} /* namespace btp */
