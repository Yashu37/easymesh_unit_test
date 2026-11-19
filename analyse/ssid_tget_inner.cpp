/*
 * HANDLER: ssid_tget_inner
 *
 * Function copied (fixes 1-4 applied, start fix n / end fix n markers) from unified-wifi-mesh src/ctrl/dm_easy_mesh_ctrl.cpp
 * (develop @ 1ba9529), dm_easy_mesh_ctrl_t::ssid_tget_inner, with fill_comma_sep() and fill_haul_type()
 * (same file). Local array: val_str[MAX_EM_BUFF_SZ = 1024] (cleared before each list); the loop runs to
 * dm->get_num_network_ssid() (m_num_net_ssids, unclamped) over m_network_ssid[EM_MAX_NET_SSIDS = 5]; the
 * event_name check reads event_name[strlen(event_name) - 1]; dm and p_data are never checked.
 * Scaffolding: one data model (sti::g_dm, NULL = no data model) whose network SSID entries are filled by
 * sti::construct_input; property_append_tail records "idx:name=value" (sti::g_rec); raw_data_set(p_data,
 * property) dereferences p_data. hash_map_get_next(NULL) is modelled as NULL (an element cannot follow NULL).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <algorithm>
#include <string>
#include <type_traits>
#include "ssid_tget_inner.h"

namespace sti {

char g_rec[16384];
int g_ids = 0;
int g_nset = 0;
dm_easy_mesh_t *g_dm = NULL;
bus_data_prop_t g_dummy_prop;
static em_ctrl_t g_ctrl;
em_ctrl_t *em_ctrl_t::get_em_ctrl_instance() { return &g_ctrl; }

void rec(unsigned int idx, const char *name, const char *val)
{
    size_t l = strlen(g_rec);
    if (l + 512 > sizeof(g_rec)) return;
    snprintf(g_rec + l, sizeof(g_rec) - l, "%u:%.200s=%.200s\n", idx, name, val);
    if (!strcmp(name, "SSID")) g_ids++;
}

/* --- copied verbatim from src/ctrl/dm_easy_mesh_ctrl.cpp --- */
/* start fix 4 */
void dm_easy_mesh_ctrl_t::fill_comma_sep(em_short_string_t str[], size_t max, char *buf, size_t buf_sz)
{
    if (buf == NULL || buf_sz == 0) {
        return;
    }
    size_t len = strnlen(buf, buf_sz - 1);
    buf[len] = '\0';
    for (size_t cnt = 0; cnt < max; cnt++) {
        size_t elen = strnlen(str[cnt], sizeof(em_short_string_t) - 1);
        if (elen == 0) {
            break;
        }
        size_t need = elen + (len ? 1 : 0);
        if (len + need + 1 > buf_sz) {
            break;
        }
        if (len) {
            buf[len++] = ',';
        }
        memcpy(buf + len, str[cnt], elen);
        len += elen;
        buf[len] = '\0';
    }
}
/* end fix 4 */

void dm_easy_mesh_ctrl_t::fill_haul_type(em_haul_type_t hauls[], size_t max, char *buf)
{
    unsigned int cnt = 0;
    const char *delim = NULL;
    const char *str;

    if (max > 8) {
        max = 8;
    }

    while (cnt < max) {
        switch (hauls [cnt]) {
            case em_haul_type_fronthaul: str = "Fronthaul"; break;
            case em_haul_type_backhaul: str = "Backhaul"; break;
            case em_haul_type_iot: str = "IoT"; break;
            case em_haul_type_configurator: str = "Configurator"; break;
            case em_haul_type_hotspot: str = "Hotspot"; break;
            default: str = NULL; break;
        }
        if (str == NULL) {
            break;
        }
        if (delim) {
            strcat(buf, delim);
        } else {
            delim = ",";
        }
        strcat(buf, str);
        ++cnt;
    }
}

bus_error_t dm_easy_mesh_ctrl_t::ssid_tget_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    const char *root = event_name;
    char val_str[MAX_EM_BUFF_SZ] = { 0 };
    bus_data_prop_t *property = NULL;

/* start fix 1 */
    if (!event_name || !p_data) {
        return bus_error_invalid_input;
    }
    if (*event_name == '\0') {
        return bus_error_invalid_operation;
    }
/* end fix 1 */
    if (*(event_name + (strlen(event_name) - 1)) != '.') {
        /* Only partial paths are valid */
        return bus_error_invalid_operation;
    }

    dm_easy_mesh_ctrl_t *dm_ctrl = em_ctrl_t::get_em_ctrl_instance()->get_dm_ctrl();
    dm_easy_mesh_t *dm = dm_ctrl->get_first_dm();
/* start fix 2 */
    if (dm == NULL) {
        return bus_error_invalid_input;
    }
/* end fix 2 */

/* start fix 3 */
    unsigned int num_ssids = std::min(dm->get_num_network_ssid(), static_cast<unsigned int>(EM_MAX_NET_SSIDS));
    for (unsigned int idx = 1; idx <= num_ssids; idx++) {
/* end fix 3 */
        dm_network_ssid_t *ssid = dm->get_network_ssid(idx - 1);
        if (ssid == NULL) {
            em_printfout("SSID is NULL");
            continue;
        }
        em_network_ssid_info_t *si = ssid->get_network_ssid_info();

        dm_ctrl->property_append_tail(&property, root, idx, "SSID", si->ssid);
        memset(val_str, 0, sizeof(val_str));
/* start fix 4 */
        dm_ctrl->fill_comma_sep(si->band, std::min(static_cast<size_t>(si->num_bands), ARRAY_SIZE(si->band)), val_str, sizeof(val_str));
/* end fix 4 */
        dm_ctrl->property_append_tail(&property, root, idx, "Band", val_str);
        dm_ctrl->property_append_tail(&property, root, idx, "Enable", si->enable);
        memset(val_str, 0, sizeof(val_str));
/* start fix 4 */
        dm_ctrl->fill_comma_sep(si->akm, std::min(static_cast<size_t>(si->num_akms), ARRAY_SIZE(si->akm)), val_str, sizeof(val_str));
/* end fix 4 */
        dm_ctrl->property_append_tail(&property, root, idx, "AKMsAllowed", val_str);
        dm_ctrl->property_append_tail(&property, root, idx, "SuiteSelector", si->suite_select);
        dm_ctrl->property_append_tail(&property, root, idx, "AdvertisementEnabled", si->advertisement);
        dm_ctrl->property_append_tail(&property, root, idx, "MFPConfig", si->mfp);
        dm_ctrl->property_append_tail(&property, root, idx, "MobilityDomain", si->mobility_domain);
        memset(val_str, 0, sizeof(val_str));
        dm_ctrl->fill_haul_type(si->haul_type, si->num_hauls, val_str);
        dm_ctrl->property_append_tail(&property, root, idx, "HaulType", val_str);
        dm_ctrl->property_append_tail(&property, root, idx, "AuthType", si->auth_type);
        dm_ctrl->property_append_tail(&property, root, idx, "VLANID", si->vlan_id);
    }

    if (property) {
        dm_ctrl->raw_data_set(p_data, property);
    }

    return bus_error_success;
}

int invoke(char *event, bool no_pdata)
{
    raw_data_t raw;
    memset(&raw, 0, sizeof(raw));
    bus_user_data_t ud;
    return (int)g_ctrl.m_data_model.ssid_tget_inner(event, no_pdata ? NULL : &raw, &ud);
}

} /* namespace sti */
