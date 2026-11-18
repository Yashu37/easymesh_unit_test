/*
 * HANDLER: stamld_tget_params
 *
 * Function copied verbatim (no fix applied yet) from unified-wifi-mesh src/ctrl/dm_easy_mesh_ctrl.cpp
 * (develop @ 1ba9529), dm_easy_mesh_ctrl_t::stamld_tget_params. Local array: path[512] (snprintf bounded by
 * sizeof(path) - 1). The loop runs to dm->get_num_assoc_sta_mld() (m_num_assoc_sta_mld, unclamped) over
 * dm->m_assoc_sta_mld[EM_MAX_ASSOC_STA_MLD = 64]; dm, ami and property are never checked.
 * Scaffolding: one data model (smt::g_dm) whose assoc STA MLD entries and STA map are filled by
 * smt::construct_input; property_append_tail records "idx:name=value" (smt::g_rec); affsta_tget_params is a
 * stub that records the path it receives (smt::g_aff_path / g_aff_calls).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <string>
#include <type_traits>
#include "stamld_tget_params.h"

namespace smt {

char g_rec[65536];
int g_rows = 0;
char g_aff_path[1024];
int g_aff_calls = 0;
dm_easy_mesh_t *g_dm = NULL;
bus_data_prop_t g_dummy_prop;
void rec(unsigned int idx, const char *name, const char *val)
{
    size_t l = strlen(g_rec);
    if (l + 700 > sizeof(g_rec)) return;
    snprintf(g_rec + l, sizeof(g_rec) - l, "%u:%.200s=%.400s\n", idx, name, val);
    if (!strcmp(name, "MLDMACAddress")) g_rows++;
}

void *hash_map_get_first(sta_map_t *m) { return (m && m->n) ? m->p[0] : NULL; }
void *hash_map_get_next(sta_map_t *m, void *cur)
{ for (int i = 0; i < m->n; i++) if (m->p[i] == cur) return i + 1 < m->n ? m->p[i + 1] : NULL; return NULL; }

static em_ctrl_t g_ctrl;
em_ctrl_t *em_ctrl_t::get_em_ctrl_instance() { return &g_ctrl; }

bus_error_t dm_easy_mesh_ctrl_t::affsta_tget_params(dm_easy_mesh_t *dm, const char *root, em_assoc_sta_mld_info_t *smi, bus_data_prop_t **property)
{ (void)dm; (void)smi; (void)property; g_aff_calls++; snprintf(g_aff_path, sizeof(g_aff_path), "%s", root); rec(0, "AFFPATH", root); return bus_error_success; }

/* --- copied verbatim from src/ctrl/dm_easy_mesh_ctrl.cpp --- */
bus_error_t dm_easy_mesh_ctrl_t::stamld_tget_params(dm_easy_mesh_t *dm, const char *root, em_ap_mld_info_t *ami, bus_data_prop_t **property)
{
    char path[512];
    bus_error_t rc = bus_error_success;
    dm_easy_mesh_ctrl_t *dm_ctrl = em_ctrl_t::get_em_ctrl_instance()->get_dm_ctrl();

    unsigned int idx = 0;
    for (unsigned int cnt = 0; cnt < dm->get_num_assoc_sta_mld(); cnt++) {
        /* First find assoc_sta_mld for this ap_mld */
        dm_assoc_sta_mld_t *sta_mld = &dm->m_assoc_sta_mld[cnt]; /* no getter? */
        em_assoc_sta_mld_info_t *smi = sta_mld->get_assoc_sta_mld_info();
        if (memcmp(ami->mac_addr, smi->ap_mld_mac_addr, sizeof(mac_address_t)) != 0) {
            /* sta_mld does not belong to this ap_mld, skip */
            continue;
        }
        /* Now find sta for this assoc_sta_mld */
        dm_sta_t *sta = static_cast<dm_sta_t *> (hash_map_get_first(dm->m_sta_map));
        em_sta_info_t *si = NULL;
        while (sta != NULL) {
            si = sta->get_sta_info();
            if (si->associated && memcmp(smi->mac_addr, si->id, sizeof(mac_addr_t)) != 0) {
                break;
            }
            sta = static_cast<dm_sta_t *> (hash_map_get_next(dm->m_sta_map, sta));
            si = NULL;
        }
        ++idx;

        dm_ctrl->property_append_tail(property, root, idx, "MLDMACAddress", smi->mac_addr);
        dm_ctrl->property_append_tail(property, root, idx, "IsbSTA", 0);
        dm_ctrl->property_append_tail(property, root, idx, "LastConnectTime", si ? si->last_conn_time : 0);
        dm_ctrl->property_append_tail(property, root, idx, "BytesReceived", si ? si->bytes_rx : 0);
        dm_ctrl->property_append_tail(property, root, idx, "BytesSent", si ? si->bytes_tx : 0);
        dm_ctrl->property_append_tail(property, root, idx, "PacketsReceived", si ? si->pkts_rx : 0);
        dm_ctrl->property_append_tail(property, root, idx, "PacketsSent", si ? si->pkts_tx : 0);
        dm_ctrl->property_append_tail(property, root, idx, "ErrorsReceived", si ? si->errors_rx : 0);
        dm_ctrl->property_append_tail(property, root, idx, "ErrorsSent", si ? si->errors_tx : 0);
        dm_ctrl->property_append_tail(property, root, idx, "RetransCount", si ? si->retrans_count : 0);
        dm_ctrl->property_append_tail(property, root, idx, "AffiliatedSTANumberOfEntries", smi->num_affiliated_sta);

        dm_ctrl->property_append_tail(property, root, idx, "STAMLDConfig.EMLMRSupport", smi->emlmr);
        dm_ctrl->property_append_tail(property, root, idx, "STAMLDConfig.EMLSRSupport", smi->emlsr);
        dm_ctrl->property_append_tail(property, root, idx, "STAMLDConfig.STRSupport", smi->str);
        dm_ctrl->property_append_tail(property, root, idx, "STAMLDConfig.NSTRSupport", smi->nstr);

        dm_ctrl->property_append_tail(property, root, idx, "WiFi7Capabilities.EMLMRSupport", smi->emlmr);
        dm_ctrl->property_append_tail(property, root, idx, "WiFi7Capabilities.EMLSRSupport", smi->emlsr);
        dm_ctrl->property_append_tail(property, root, idx, "WiFi7Capabilities.STRSupport", smi->str);
        dm_ctrl->property_append_tail(property, root, idx, "WiFi7Capabilities.NSTRSupport", smi->nstr);

        snprintf(path, sizeof(path) - 1, "%s%d.AffiliatedSTA.", root, idx);
        dm_ctrl->affsta_tget_params(dm, path, smi, property);
    }

    return rc;
}

int invoke(const char *root, bool no_dm, bool no_ami, bool no_prop)
{
    bus_data_prop_t *property = NULL;
    return (int)g_ctrl.m_data_model.stamld_tget_params(no_dm ? NULL : g_dm, root, no_ami ? NULL : &g_ami, no_prop ? NULL : &property);
}

} /* namespace smt */
