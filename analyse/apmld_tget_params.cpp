/*
 * HANDLER: apmld_tget_params
 *
 * Function copied verbatim (no fix applied yet) from unified-wifi-mesh src/ctrl/dm_easy_mesh_ctrl.cpp
 * (develop @ 1ba9529), dm_easy_mesh_ctrl_t::apmld_tget_params. Local array: path[512] (snprintf bounded by
 * sizeof(path) - 1). The loop runs to dm->get_num_ap_mld() (m_num_ap_mld, unclamped) over
 * dm->m_ap_mld[EM_MAX_AP_MLD = 64]; dm and property are never checked.
 * Scaffolding: one data model (apt::g_dm) whose AP MLD entries are filled by apt::construct_input;
 * property_append_tail records "idx:name=value" (apt::g_rec); affap_tget_params and stamld_tget_params are
 * stubs that record the path they receive (lines "0:AFFPATH=" / "0:STAPATH=").
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <string>
#include <type_traits>
#include "apmld_tget_params.h"

namespace apt {

char g_rec[65536];
int g_rows = 0;
char g_aff_path[1024];
dm_easy_mesh_t *g_dm = NULL;
bus_data_prop_t g_dummy_prop;
void rec(unsigned int idx, const char *name, const char *val)
{
    size_t l = strlen(g_rec);
    if (l + 700 > sizeof(g_rec)) return;
    snprintf(g_rec + l, sizeof(g_rec) - l, "%u:%.200s=%.400s\n", idx, name, val);
    if (!strcmp(name, "MLDMACAddress")) g_rows++;
}

static em_ctrl_t g_ctrl;
em_ctrl_t *em_ctrl_t::get_em_ctrl_instance() { return &g_ctrl; }

bus_error_t dm_easy_mesh_ctrl_t::affap_tget_params(dm_easy_mesh_t *dm, const char *root, em_ap_mld_info_t *ami, bus_data_prop_t **property)
{ (void)dm; (void)ami; (void)property; snprintf(g_aff_path, sizeof(g_aff_path), "%s", root); rec(0, "AFFPATH", root); return bus_error_success; }
bus_error_t dm_easy_mesh_ctrl_t::stamld_tget_params(dm_easy_mesh_t *dm, const char *root, em_ap_mld_info_t *ami, bus_data_prop_t **property)
{ (void)dm; (void)ami; (void)property; snprintf(g_aff_path, sizeof(g_aff_path), "%s", root); rec(0, "STAPATH", root); return bus_error_success; }

/* --- copied verbatim from src/ctrl/dm_easy_mesh_ctrl.cpp --- */
bus_error_t dm_easy_mesh_ctrl_t::apmld_tget_params(dm_easy_mesh_t *dm, const char *root, bus_data_prop_t **property)
{
    char path[512];
    bus_error_t rc = bus_error_success;
    dm_easy_mesh_ctrl_t *dm_ctrl = em_ctrl_t::get_em_ctrl_instance()->get_dm_ctrl();

    for (unsigned int idx = 1; idx <= dm->get_num_ap_mld(); idx++) {
        /* Get ap_mld dm object for numeric instance */
        dm_ap_mld_t *ap_mld = dm->get_ap_mld(idx - 1);
        if (ap_mld == NULL) {
            continue;
        }
        /* Get info structure for ap_mld object */
        em_ap_mld_info_t *ami = ap_mld->get_ap_mld_info();

        dm_ctrl->property_append_tail(property, root, idx, "MLDMACAddress", ami->mac_addr);
        dm_ctrl->property_append_tail(property, root, idx, "AffiliatedAPNumberOfEntries", ami->num_affiliated_ap);
        dm_ctrl->property_append_tail(property, root, idx, "STAMLDNumberOfEntries", 0);

        dm_ctrl->property_append_tail(property, root, idx, "APMLDConfig.EMLMREnabled", ami->emlmr);
        dm_ctrl->property_append_tail(property, root, idx, "APMLDConfig.EMLSREnabled", ami->emlsr);
        dm_ctrl->property_append_tail(property, root, idx, "APMLDConfig.STREnabled", ami->str);
        dm_ctrl->property_append_tail(property, root, idx, "APMLDConfig.NSTREnabled", ami->nstr);

        snprintf(path, sizeof(path) - 1, "%s%d.AffiliatedAP.", root, idx);
        dm_ctrl->affap_tget_params(dm, path, ami, property);

        snprintf(path, sizeof(path) - 1, "%s%d.STAMLD.", root, idx);
        dm_ctrl->stamld_tget_params(dm, path, ami, property);
    }

    return rc;
}

int invoke(const char *root, bool no_dm, bool no_prop)
{
    bus_data_prop_t *property = NULL;
    return (int)g_ctrl.m_data_model.apmld_tget_params(no_dm ? NULL : g_dm, root, no_prop ? NULL : &property);
}

} /* namespace apt */
