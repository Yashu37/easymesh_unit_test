/*
 * HANDLER: wf6ap_get_inner
 *
 * Function copied VERBATIM from unified-wifi-mesh src/ctrl/dm_easy_mesh_ctrl.cpp
 * (develop @ 1ba9529), dm_easy_mesh_ctrl_t::wf6ap_get_inner, with get_table_instance()
 * (same file, verbatim). Local arrays: instance[32], mcsnss_str[256], temp[32],
 * and the array accesses dm->m_radio[radio_instance - 1] (EM_MAX_BANDS = 3),
 * rci->wifi6_cap.roles[i] (MAP_AP_ROLE_MAX = 2), role->sprt_tx_rx_mcs[j] (MAX_MCS = 3).
 * Scaffolding: a list of data models (w6g::dm_spec_t) with a radio table / radio caps;
 * raw_data_set records the value it is given.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <string>
#include <type_traits>
#include "wf6ap_get_inner.h"

namespace w6g {

char g_val[64];
int g_nset = 0;
dm_easy_mesh_t *g_dm[W6G_MAXDM + 1];
int g_ndm = 0;

class dm_easy_mesh_ctrl_t {
public:
    const char* get_table_instance(const char *src, char *instance, size_t max_len, bool *is_num);
    dm_easy_mesh_t *get_first_dm() { return g_ndm ? g_dm[0] : NULL; }
    dm_easy_mesh_t *get_next_dm(dm_easy_mesh_t *dm)
    { for (int i = 0; i < g_ndm; i++) if (g_dm[i] == dm) return (i + 1 < g_ndm) ? g_dm[i + 1] : NULL; return NULL; }
    bus_error_t raw_data_set(raw_data_t *p, const char *v) { (void)p; g_nset++; snprintf(g_val, sizeof(g_val), "%s", v); return bus_error_success; }
    template <typename T>
    typename std::enable_if<std::is_arithmetic<T>::value, bus_error_t>::type
    raw_data_set(raw_data_t *p, T v) { (void)p; g_nset++; snprintf(g_val, sizeof(g_val), "%lld", (long long)v); return bus_error_success; }
    bus_error_t wf6ap_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
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
const char* dm_easy_mesh_ctrl_t::get_table_instance(const char *src, char *instance, size_t max_len, bool *is_num)
{
	char *dst = instance;
	size_t len = 0;

    src = strstr(src, ".");
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

bus_error_t dm_easy_mesh_ctrl_t::wf6ap_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    (void) user_data;
    const char *name = event_name;
    const char *param;
    char instance[MAX_INSTANCE_LEN] = { 0 };
    bool is_num;
    int device_instance = 0, radio_instance = 0;
    bus_error_t rc = bus_error_invalid_input;
    em_wifi6_role_wire_t role_temp;
    em_wifi6_role_wire_t *role = &role_temp;

    if (!name || !p_data) {
        return bus_error_invalid_input;
    }

    param = strrchr(name, '.');
    if (param == NULL) {
        return bus_error_invalid_input;
    }
    ++param;

    dm_easy_mesh_ctrl_t *dm_ctrl = em_ctrl_t::get_em_ctrl_instance()->get_dm_ctrl();
    name += sizeof(DATAELEMS_NETWORK);
    name = dm_ctrl->get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    device_instance = is_num ? atoi(instance) : 0;

    dm_easy_mesh_t *dm = dm_ctrl->get_first_dm();
    if (dm == NULL || (dm->get_id() != device_instance)) {
        dm = dm_ctrl->get_next_dm(dm);
    }

    if(dm == NULL) {
        em_printfout("dm is NULL");
        return bus_error_invalid_input;
    }

    name = dm_ctrl->get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    radio_instance = is_num ? atoi(instance) : 0;
    dm_radio_t *radio = &dm->m_radio[radio_instance - 1];
    if (radio == NULL) {
        em_printfout("radio is NULL\n");
        return bus_error_invalid_input;
    }
    em_radio_info_t *ri = radio->get_radio_info();

    em_printfout("device_instance:%d, radio_instance:%d, ruid:%s", device_instance, radio_instance, util::mac_to_string(ri->id.ruid).c_str());
    dm_radio_cap_t *radio_cap = dm->get_radio_cap(ri->id.ruid);
    if (radio_cap == NULL) {
        em_printfout("radio_cap is NULL for %s\n", util::mac_to_string(ri->id.ruid).c_str());
        return bus_error_invalid_input;
    }
    em_radio_cap_info_t *rci = radio_cap->get_radio_cap_info();
    unsigned int i;

    for (i = 0; i < rci->wifi6_cap.num_role; i++) {
        char mcsnss_str[256] = { 0 };
        memcpy(&role_temp, &rci->wifi6_cap.roles[i], sizeof(em_wifi6_role_wire_t));

        if (strcmp(param, "HE160") == 0) {
            rc = dm_ctrl->raw_data_set(p_data, static_cast<bool>(role->role_head.he_160));
        } else if (strcmp(param, "HE8080") == 0) {
            rc = dm_ctrl->raw_data_set(p_data, static_cast<bool>(role->role_head.he_8080));
        } else if (strcmp(param, "MCSNSS") == 0) {
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
            rc = dm_ctrl->raw_data_set(p_data, mcsnss_str);
        } else if (strcmp(param, "SUBeamformer") == 0) {
            rc = dm_ctrl->raw_data_set(p_data, static_cast<bool>(role->role_tail.su_beam_former));
        } else if (strcmp(param, "SUBeamformee") == 0) {
            rc = dm_ctrl->raw_data_set(p_data, static_cast<bool>(role->role_tail.su_beam_formee));
        } else if (strcmp(param, "MUBeamformer") == 0) {
            rc = dm_ctrl->raw_data_set(p_data, static_cast<bool>(role->role_tail.mu_beam_former));
        } else if (strcmp(param, "Beamformee80orLess") == 0) {
            rc = dm_ctrl->raw_data_set(p_data, static_cast<bool>(role->role_tail.beam_formee_sts_l80));
        } else if (strcmp(param, "BeamformeeAbove80") == 0) {
            rc = dm_ctrl->raw_data_set(p_data, static_cast<bool>(role->role_tail.beam_formee_sts_g80));
        } else if (strcmp(param, "ULMUMIMO") == 0) {
            rc = dm_ctrl->raw_data_set(p_data, static_cast<bool>(role->role_tail.ul_mumimo));
        } else if (strcmp(param, "ULOFDMA") == 0) {
            rc = dm_ctrl->raw_data_set(p_data, static_cast<bool>(role->role_tail.ul_ofdma));
        } else if (strcmp(param, "DLOFDMA") == 0) {
            rc = dm_ctrl->raw_data_set(p_data, static_cast<bool>(role->role_tail.dl_ofdma));
        } else if (strcmp(param, "MaxDLMUMIMO") == 0) {
            rc = dm_ctrl->raw_data_set(p_data, static_cast<unsigned int>(role->role_tail.max_dl_mumimo_tx));
        } else if (strcmp(param, "MaxULMUMIMO") == 0) {
            rc = dm_ctrl->raw_data_set(p_data, static_cast<unsigned int>(role->role_tail.max_ul_mumimo_rx));
        } else if (strcmp(param, "MaxDLOFDMA") == 0) {
            rc = dm_ctrl->raw_data_set(p_data, static_cast<unsigned int>(role->role_tail.max_dl_ofdma_tx));
        } else if (strcmp(param, "MaxULOFDMA") == 0) {
            rc = dm_ctrl->raw_data_set(p_data, static_cast<unsigned int>(role->role_tail.max_ul_ofdma_rx));
        } else if (strcmp(param, "RTS") == 0) {
            rc = dm_ctrl->raw_data_set(p_data, static_cast<bool>(role->role_tail.rts));
        } else if (strcmp(param, "MURTS") == 0) {
            rc = dm_ctrl->raw_data_set(p_data, static_cast<bool>(role->role_tail.mu_rts));
        } else if (strcmp(param, "MultiBSSID") == 0) {
            rc = dm_ctrl->raw_data_set(p_data, static_cast<bool>(role->role_tail.multi_bssid));
        } else if (strcmp(param, "MUEDCA") == 0) {
            rc = dm_ctrl->raw_data_set(p_data, static_cast<bool>(role->role_tail.mu_edca));
        } else if (strcmp(param, "TWTRequestor") == 0) {
            rc = dm_ctrl->raw_data_set(p_data, static_cast<bool>(role->role_tail.twt_req));
        } else if (strcmp(param, "TWTResponder") == 0) {
            rc = dm_ctrl->raw_data_set(p_data, static_cast<bool>(role->role_tail.twt_resp));
        } else if (strcmp(param, "SpatialReuse") == 0) {
            rc = dm_ctrl->raw_data_set(p_data, static_cast<bool>(role->role_tail.spatial_reuse));
        } else if (strcmp(param, "AnticipatedChannelUsage") == 0) {
            rc = dm_ctrl->raw_data_set(p_data, static_cast<bool>(role->role_tail.anticipated_channel_usage));
        } else {
            em_printfout("Invalid WiFi6APRole param: %s", param);
            rc = bus_error_invalid_input;
        }
    }
    return rc;
}

int invoke(const char *event, bool no_pdata)
{
    raw_data_t raw;
    memset(&raw, 0, sizeof(raw));
    bus_user_data_t ud;
    return (int)g_ctrl.m_data_model.wf6ap_get_inner((char *)event, no_pdata ? NULL : &raw, &ud);
}

} /* namespace w6g */
