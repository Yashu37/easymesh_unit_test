/*
 * HANDLER: wf6ap_tget_params
 *
 * Function copied VERBATIM from unified-wifi-mesh src/ctrl/dm_easy_mesh_ctrl.cpp
 * (develop @ 1ba9529), dm_easy_mesh_ctrl_t::wf6ap_tget_params. Local arrays: mcsnss_str[256], temp[32],
 * and the accesses rci->wifi6_cap.roles[i] (MAP_AP_ROLE_MAX = 2, bound is the data-model value num_role),
 * role->sprt_tx_rx_mcs[j] (MAX_MCS = 3).
 * Scaffolding: one radio cap (the lookup dm->get_radio_cap() is a separate function, already tracked for
 * radio_tget_params, so it is a plain RUID match here); property_append_tail records "name=value".
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <string>
#include <type_traits>
#include "wf6ap_tget_params.h"

namespace wtp {

char g_rec[16384];
int g_roles = 0;
dm_easy_mesh_t *g_dm = NULL;
static bus_data_prop_t g_dummy_prop;
static void rec(const char *name, const char *val)
{
    size_t l = strlen(g_rec);
    if (l + 256 > sizeof(g_rec)) return;
    snprintf(g_rec + l, sizeof(g_rec) - l, "%s=%s\n", name, val);
    if (!strcmp(name, "HE160")) g_roles++;
}

class dm_easy_mesh_ctrl_t {
public:
    void property_append_tail(bus_data_prop_t **prop, const char *root, const char *name, const char *v)
    { (void)root; if (!*prop) *prop = &g_dummy_prop; rec(name, v); }
    template <typename T>
    typename std::enable_if<std::is_arithmetic<T>::value>::type
    property_append_tail(bus_data_prop_t **prop, const char *root, const char *name, T v)
    { char s[32]; (void)root; if (!*prop) *prop = &g_dummy_prop; snprintf(s, sizeof(s), "%lld", (long long)v); rec(name, s); }
    bus_error_t wf6ap_tget_params(dm_easy_mesh_t *dm, const char *root, em_radio_info_t *ri, bus_data_prop_t **property, unsigned int idx);
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
bus_error_t dm_easy_mesh_ctrl_t::wf6ap_tget_params(dm_easy_mesh_t *dm, const char *root, em_radio_info_t *ri, bus_data_prop_t **property, unsigned int idx)
{
    bus_error_t rc = bus_error_success;
    unsigned int i;
    (void) idx; /* WiFi6APRole is an object (not a table): no row instance under it */
    em_wifi6_role_wire_t role_temp;
    em_wifi6_role_wire_t *role = &role_temp;

    dm_easy_mesh_ctrl_t *dm_ctrl = em_ctrl_t::get_em_ctrl_instance()->get_dm_ctrl();
    dm_radio_cap_t *radio_cap = dm->get_radio_cap(ri->id.ruid);
    if (radio_cap == NULL) {
        return rc;
    }
    em_radio_cap_info_t *rci = radio_cap->get_radio_cap_info();

    for (i = 0; i < rci->wifi6_cap.num_role; i++) {
        char mcsnss_str[256] = { 0 };
        memcpy(role, &rci->wifi6_cap.roles[i], sizeof(em_wifi6_role_wire_t));

        int num_maps = role->role_head.mcs_nss_num / EM_MIN_HE_MCS_LEN;
        for (int j = 0; j < num_maps && j < MAX_MCS; j++) {
            char temp[32];
            snprintf(temp, sizeof(temp),
                    "%x%x",
                    role->sprt_tx_rx_mcs[j].tx_he_mcs,
                    role->sprt_tx_rx_mcs[j].rx_he_mcs);
            strncat(mcsnss_str, temp,
                    sizeof(mcsnss_str) - strlen(mcsnss_str) - 1);
        }
        dm_ctrl->property_append_tail(property, root, "HE160", static_cast<bool>(role->role_head.he_160));
        dm_ctrl->property_append_tail(property, root, "HE8080", static_cast<bool>(role->role_head.he_8080));
        dm_ctrl->property_append_tail(property, root, "MCSNSS", mcsnss_str);
        dm_ctrl->property_append_tail(property, root, "SUBeamformer", static_cast<bool>(role->role_tail.su_beam_former));
        dm_ctrl->property_append_tail(property, root, "SUBeamformee", static_cast<bool>(role->role_tail.su_beam_formee));
        dm_ctrl->property_append_tail(property, root, "MUBeamformer", static_cast<bool>(role->role_tail.mu_beam_former));
        dm_ctrl->property_append_tail(property, root, "Beamformee80orLess", static_cast<bool>(role->role_tail.beam_formee_sts_l80));
        dm_ctrl->property_append_tail(property, root, "BeamformeeAbove80", static_cast<bool>(role->role_tail.beam_formee_sts_g80));
        dm_ctrl->property_append_tail(property, root, "ULMUMIMO", static_cast<bool>(role->role_tail.ul_mumimo));
        dm_ctrl->property_append_tail(property, root, "ULOFDMA", static_cast<bool>(role->role_tail.ul_ofdma));
        dm_ctrl->property_append_tail(property, root, "DLOFDMA", static_cast<bool>(role->role_tail.dl_ofdma));
        dm_ctrl->property_append_tail(property, root, "MaxDLMUMIMO", static_cast<unsigned int>(role->role_tail.max_dl_mumimo_tx));
        dm_ctrl->property_append_tail(property, root, "MaxULMUMIMO", static_cast<unsigned int>(role->role_tail.max_ul_mumimo_rx));
        dm_ctrl->property_append_tail(property, root, "MaxDLOFDMA", static_cast<unsigned int>(role->role_tail.max_dl_ofdma_tx));
        dm_ctrl->property_append_tail(property, root, "MaxULOFDMA", static_cast<unsigned int>(role->role_tail.max_ul_ofdma_rx));
        dm_ctrl->property_append_tail(property, root, "RTS", static_cast<bool>(role->role_tail.rts));
        dm_ctrl->property_append_tail(property, root, "MURTS", static_cast<bool>(role->role_tail.mu_rts));
        dm_ctrl->property_append_tail(property, root, "MultiBSSID", static_cast<bool>(role->role_tail.multi_bssid));
        dm_ctrl->property_append_tail(property, root, "MUEDCA", static_cast<bool>(role->role_tail.mu_edca));
        dm_ctrl->property_append_tail(property, root, "TWTRequestor", static_cast<bool>(role->role_tail.twt_req));
        dm_ctrl->property_append_tail(property, root, "TWTResponder", static_cast<bool>(role->role_tail.twt_resp));
        dm_ctrl->property_append_tail(property, root, "SpatialReuse", static_cast<bool>(role->role_tail.spatial_reuse));
        dm_ctrl->property_append_tail(property, root, "AnticipatedChannelUsage", static_cast<bool>(role->role_tail.anticipated_channel_usage));
    }

    return rc;
}

int invoke(const char *root, bool other_radio)
{
    bus_data_prop_t *prop = NULL;
    em_radio_info_t ri;
    memset(&ri, 0, sizeof(ri));
    unsigned char m[6] = {2, 0, 0, 0, 0, (unsigned char)(other_radio ? 2 : 1)};
    memcpy(ri.id.ruid, m, 6);
    return (int)g_ctrl.m_data_model.wf6ap_tget_params(g_dm, root, &ri, &prop, 1);
}

} /* namespace wtp */
