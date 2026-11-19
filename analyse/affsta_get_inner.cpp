/*
 * HANDLER: affsta_get_inner
 *
 * Function copied from unified-wifi-mesh src/ctrl/dm_easy_mesh_ctrl.cpp (develop @ 1ba9529),
 * dm_easy_mesh_ctrl_t::affsta_get_inner (fixes 1-3 applied, start fix n / end fix n markers), with get_table_instance(), get_dm_ap_mld() and get_dm_sta_mld() (same file).
 * Local arrays: instance[32]; the array accesses smi->affiliated_sta[idx - 1] (EM_MAX_AP_MLD = 64, while
 * num_affiliated_sta is an unsigned char) and name += sizeof(DATAELEMS_NETWORK). The handler already rejects a NULL
 * event_name / p_data. Scaffolding: one device 1 with 2 AP MLDs, 3 STA MLDs and a STA map; raw_data_set records the value
 * it is given. NOTE: get_dm_sta_mld() (separate function) counts the STA MLDs that do NOT belong to the AP MLD for a numeric
 * instance and get_dm_ap_mld() returns the last AP MLD for an unknown alias; the harness therefore selects the STA MLD by
 * its MAC alias and never uses an unknown AP MLD alias.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <string>
#include <type_traits>
#include "affsta_get_inner.h"

namespace afg {

char g_val[AFG_VAL_SZ];
int g_nset = 0;
dm_easy_mesh_t *g_dm = NULL;

void *hash_map_get_first(sta_map_t *m) { return (m && m->n) ? m->p[0] : NULL; }
void *hash_map_get_next(sta_map_t *m, void *cur)
{ for (int i = 0; i < m->n; i++) if (m->p[i] == cur) return i + 1 < m->n ? m->p[i + 1] : NULL; return NULL; }

static em_ctrl_t g_ctrl;
em_ctrl_t *em_ctrl_t::get_em_ctrl_instance() { return &g_ctrl; }

/* --- copied verbatim from src/ctrl/dm_easy_mesh_ctrl.cpp --- */
const char* dm_easy_mesh_ctrl_t::get_table_instance(const char *src, char *instance, size_t max_len, bool *is_num)
{
	char *dst = instance;
	size_t len = 0;

/* start fix 2 */
    if (src == NULL) {
        return NULL;
    }
    src = strstr(src, ".");
    if (src == NULL) {
        return NULL;
    }
/* end fix 2 */
    ++src;

	if (*src == '[') {
		*is_num = false;
		++src;
		while (*src && *src != ']' && ++len < max_len) {
			*dst++ = *src++;
		}
		*dst++ = 0;
		src += 2;
	} else {
		*is_num = true;
		while (*src && *src != '.' && ++len < max_len) {
			*dst++ = *src++;
		}
		*dst++ = 0;
		src++;
	}

	return src;
}

dm_ap_mld_t *dm_easy_mesh_ctrl_t::get_dm_ap_mld(dm_easy_mesh_t *dm, char *instance, bool is_num)
{
    dm_ap_mld_t *ap_mld = NULL;

    if (is_num) {
        unsigned int idx = static_cast<unsigned int>(atoi(instance) - 1);
        if (idx >= dm->get_num_ap_mld()) {
            return NULL;
        }
        ap_mld = dm->get_ap_mld(idx);
        return ap_mld;
    }

    for (unsigned int i = 0; i < dm->get_num_ap_mld(); i++) {
        char mac_str[18];
        ap_mld = dm->get_ap_mld(i);
        if (ap_mld == NULL) {
            continue;
        }
        em_ap_mld_info_t *ami = ap_mld->get_ap_mld_info();
        dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (ami->mac_addr), mac_str);
        if (strcmp(instance, mac_str) == 0) {
            return ap_mld;
        }
    }

    return ap_mld;
}

dm_assoc_sta_mld_t *dm_easy_mesh_ctrl_t::get_dm_sta_mld(dm_easy_mesh_t *dm, em_ap_mld_info_t *ami, char *instance, bool is_num)
{
    dm_assoc_sta_mld_t *sta_mld = NULL;

    if (is_num) {
        unsigned int cnt = 0;
        unsigned int idx = static_cast<unsigned int>(atoi(instance) - 1);
        for (unsigned int i = 0; i < dm->get_num_assoc_sta_mld(); i++) {
            dm_assoc_sta_mld_t *sta_mld = &dm->m_assoc_sta_mld[i]; /* no getter? */
            em_assoc_sta_mld_info_t *smi = sta_mld->get_assoc_sta_mld_info();
            if (memcmp(ami->mac_addr, smi->ap_mld_mac_addr, sizeof(mac_address_t)) != 0) {
                /* sta_mld does belong to ap_mld */
                ++cnt;
                if (cnt == idx) {
                    return sta_mld;
                }
            }
        }
    }

    for (unsigned int i = 0; i < dm->get_num_assoc_sta_mld(); i++) {
        char mac_str[18];
        dm_assoc_sta_mld_t *sta_mld = &dm->m_assoc_sta_mld[i]; /* no getter? */
        em_assoc_sta_mld_info_t *smi = sta_mld->get_assoc_sta_mld_info();
        dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (smi->mac_addr), mac_str);
        if (strcmp(instance, mac_str) == 0) {
            return sta_mld;
        }
    }

    return sta_mld;
}

bus_error_t dm_easy_mesh_ctrl_t::affsta_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    (void) user_data;
    const char *name = event_name;
    const char *param;
    char instance[MAX_INSTANCE_LEN] = { 0 };
    bool is_num;
    bus_error_t rc;

    if (!name || !p_data) {
        return bus_error_invalid_input;
    }

    param = strrchr(name, '.');
    if (param == NULL) {
        return bus_error_invalid_input;
    }
    ++param;

    dm_easy_mesh_ctrl_t *dm_ctrl = em_ctrl_t::get_em_ctrl_instance()->get_dm_ctrl();

    /* Extract device instance (numeric or alias) and find the dm object for
     * that device instance */
/* start fix 1 */
    if (strlen(name) < sizeof(DATAELEMS_NETWORK)) {
        return bus_error_invalid_input;
    }
/* end fix 1 */
    name += sizeof(DATAELEMS_NETWORK);
    name = dm_ctrl->get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
/* start fix 2 */
    if (name == NULL) {
        return bus_error_invalid_input;
    }
/* end fix 2 */
    dm_easy_mesh_t *dm = dm_ctrl->get_dm_easy_mesh(instance, is_num);
    if (dm == NULL) {
        em_printfout("Device not found");
        return bus_error_invalid_namespace;
    }

    /* Extract ap_mld instance (numeric or alias), find the ap_mld dm object
     * for that instance, and finally get info struct for ap_mld dm object */
    name = dm_ctrl->get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
/* start fix 2 */
    if (name == NULL) {
        return bus_error_invalid_input;
    }
/* end fix 2 */
    dm_ap_mld_t *ap_mld = dm_ctrl->get_dm_ap_mld(dm, instance, is_num);
    if (ap_mld == NULL) {
        em_printfout("APMLD not found");
        return bus_error_invalid_namespace;
    }
    em_ap_mld_info_t *ami = ap_mld->get_ap_mld_info();

    /* Extract assoc_sta_mld instance (numeric or alias), find the
     * assoc_sta_mld dm object for that instance, and finally get info struct
     * for assoc_sta_mld dm object */
    name = dm_ctrl->get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
/* start fix 2 */
    if (name == NULL) {
        return bus_error_invalid_input;
    }
/* end fix 2 */
    dm_assoc_sta_mld_t *sta_mld = dm_ctrl->get_dm_sta_mld(dm, ami, instance, is_num);
    if (sta_mld == NULL) {
        em_printfout("STAMLD not found");
        return bus_error_invalid_namespace;
    }
    em_assoc_sta_mld_info_t *smi = sta_mld->get_assoc_sta_mld_info();

    /* Extract aff_sta instance and get info struct for that aff_sta */
    name = dm_ctrl->get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
/* start fix 2 */
    if (name == NULL) {
        return bus_error_invalid_input;
    }
/* end fix 2 */
    int idx = atoi(instance);
/* start fix 3 */
    int num_aff = smi->num_affiliated_sta > EM_MAX_AP_MLD ? EM_MAX_AP_MLD : smi->num_affiliated_sta;
    if (!is_num || idx <= 0 || idx > num_aff) {
/* end fix 3 */
        em_printfout("AffiliatedSTA not found");
        return bus_error_invalid_namespace;
    }
    em_affiliated_sta_info_t *asi = &smi->affiliated_sta[idx - 1];

    dm_sta_t *sta = static_cast<dm_sta_t *> (hash_map_get_first(dm->m_sta_map));
    em_sta_info_t *si = NULL;
    while (sta != NULL) {
        si = sta->get_sta_info();
        if (si->associated && memcmp(asi->link_addr, si->id, sizeof(mac_addr_t)) != 0) {
            break;
        }
        sta = static_cast<dm_sta_t *> (hash_map_get_next(dm->m_sta_map, sta));
        si = NULL;
    }

    if (strcmp(param, "MACAddress") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, asi->link_addr);
    } else if (strcmp(param, "BSSID") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, asi->bssid);
    } else if (strcmp(param, "BytesSent") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, si ? si->bytes_tx : 0);
    } else if (strcmp(param, "BytesReceived") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, si ? si->bytes_rx : 0);
    } else if (strcmp(param, "PacketsSent") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, si ? si->pkts_tx : 0);
    } else if (strcmp(param, "PacketsReceived") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, si ? si->pkts_rx : 0);
    } else if (strcmp(param, "ErrorsSent") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, si ? si->errors_tx : 0);
    } else if (strcmp(param, "SignalStrength") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, si ? si->rcpi : 0);
    } else if (strcmp(param, "EstMACDataRateDownlink") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, si ? si->est_dl_rate : 0);
    } else if (strcmp(param, "EstMACDataRateUplink") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, si ? si->est_ul_rate : 0);
    } else {
        em_printfout("Invalid param: %s", param);
        rc = bus_error_destination_not_found;
    }

    return rc;
}

int invoke(const char *event, bool no_pdata)
{
    raw_data_t raw;
    memset(&raw, 0, sizeof(raw));
    bus_user_data_t ud;
    return (int)g_ctrl.m_data_model.affsta_get_inner(const_cast<char *>(event), no_pdata ? NULL : &raw, &ud);
}

} /* namespace afg */
