/*
 * HANDLER: bss_get_inner
 *
 * Function copied from unified-wifi-mesh src/ctrl/dm_easy_mesh_ctrl.cpp (develop @ 1ba9529),
 * dm_easy_mesh_ctrl_t::bss_get_inner, with get_table_instance() (same file). Local arrays: val_str[MAX_EM_BUFF_SZ],
 * instance[32]; the array accesses dm->m_radio[radio_instance - 1] (EM_MAX_BANDS = 3), dm->get_bss_info(i) for
 * i < dm->m_num_bss (m_bss[EM_MAX_BSSS = 24]) and name += sizeof(DATAELEMS_NETWORK). The handler already rejects a NULL
 * event_name / p_data. Scaffolding: one device 1 with 3 radios and a BSS list; fill_bss_akms_allowed is a stub that
 * writes "psk,sae" (fronthaul BSS) / "wpa2,sae-b" (backhaul BSS) for the matching side and "" for the other.
 * raw_data_set records the value it is given. NOTE: for the QMDescriptor and LinkRemovalImminent parameters the
 * handler returns the never assigned local rc (indeterminate value); the harness has no case for them.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <string>
#include <type_traits>
#include "bss_get_inner.h"

namespace bgi {

char g_val[BGI_VAL_SZ];
int g_nset = 0;
dm_easy_mesh_t *g_dm = NULL;

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

bus_error_t dm_easy_mesh_ctrl_t::bss_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    (void) user_data;
    const char *name = event_name;
    const char *param;
    char val_str[MAX_EM_BUFF_SZ] = { 0 };
    unsigned int i = 0;
    int count = 0;
    char instance[MAX_INSTANCE_LEN] = { 0 };
    bool is_num;
    int radio_instance = 0, bss_instance = 0;
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
    name += sizeof(DATAELEMS_NETWORK);
    name = dm_ctrl->get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    dm_easy_mesh_t *dm = dm_ctrl->get_dm_easy_mesh(instance, is_num);
    if (dm == NULL) {
        printf("device not found\n");
        return bus_error_invalid_namespace;
    }

    name = dm_ctrl->get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    radio_instance = is_num ? atoi(instance) : 0;
    dm_radio_t *radio = &dm->m_radio[radio_instance - 1];
    if (radio == NULL) {
        em_printfout("radio is NULL\n");
        return bus_error_invalid_input;
    }
    em_radio_info_t *ri = radio->get_radio_info();
    em_bss_info_t *bi;
    mac_addr_str_t  radio_str, bss_str;

    name = dm_ctrl->get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    bss_instance = is_num ? atoi(instance) : 0;
    for(i = 0; i < dm->m_num_bss; i++) {
        bi = dm->get_bss_info(i);
        dm_easy_mesh_t::macbytes_to_string(bi->ruid.mac, bss_str);
        dm_easy_mesh_t::macbytes_to_string(ri->id.ruid, radio_str);
        if(memcmp(ri->id.ruid, bi->ruid.mac, sizeof(mac_address_t)) == 0 &&
           memcmp(bi->bssid.mac, ZERO_MAC_ADDR, sizeof(ZERO_MAC_ADDR)) != 0) {
            count++;
            if(count == bss_instance) {
                break;
            }
        }
    }
    if (bss_instance < 1 || count != bss_instance) {
        em_printfout("BSS not found");
        return bus_error_invalid_namespace;
    }

    if (strcmp(param, "BSSID") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, bi->bssid.mac);
    } else if (strcmp(param, "SSID") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, bi->ssid);
    } else if (strcmp(param, "Enabled") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, bi->enabled);
    } else if (strcmp(param, "LastChange") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, bi->last_change);
    } else if (strcmp(param, "TimeStamp") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, bi->timestamp);
    } else if (strcmp(param, "UnicastBytesSent") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, bi->unicast_bytes_sent);
    } else if (strcmp(param, "UnicastBytesReceived") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, bi->unicast_bytes_rcvd);
    } else if (strcmp(param, "MulticastBytesSent") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, bi->multicast_bytes_sent);
    } else if (strcmp(param, "MulticastBytesReceived") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, bi->multicast_bytes_rcvd);
    } else if (strcmp(param, "BroadcastBytesSent") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, bi->broadcast_bytes_sent);
    } else if (strcmp(param, "BroadcastBytesReceived") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, bi->broadcast_bytes_rcvd);
    } else if (strcmp(param, "EstServiceParametersBE") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, bi->est_svc_params_be);
    } else if (strcmp(param, "EstServiceParametersBK") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, bi->est_svc_params_bk);
    } else if (strcmp(param, "EstServiceParametersVI") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, bi->est_svc_params_vi);
    } else if (strcmp(param, "EstServiceParametersVO") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, bi->est_svc_params_vo);
    } else if (strcmp(param, "ByteCounterUnits") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, bi->byte_counter_units);
    } else if (strcmp(param, "Profile1bSTAsDisallowed") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, bi->profile_1b_sta_allowed);
    } else if (strcmp(param, "Profile2bSTAsDisallowed") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, bi->profile_2b_sta_allowed);
    } else if (strcmp(param, "AssociationAllowanceStatus") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, bi->assoc_allowed_status);
    } else if (strcmp(param, "BackhaulUse") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, (bi->id.haul_type == em_haul_type_backhaul));
    } else if (strcmp(param, "FronthaulUse") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, (bi->id.haul_type == em_haul_type_fronthaul));
    } else if (strcmp(param, "R1disallowed") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, bi->r1_disallowed);
    } else if (strcmp(param, "R2disallowed") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, bi->r2_disallowed);
    } else if (strcmp(param, "MultiBSSID") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, bi->multi_bssid);
    } else if (strcmp(param, "TransmittedBSSID") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, bi->transmitted_bssid);
    } else if (strcmp(param, "FronthaulAKMsAllowed") == 0) {
        dm_ctrl->fill_bss_akms_allowed(dm, bi, false, val_str, sizeof(val_str));
        rc = dm_ctrl->raw_data_set(p_data, val_str);
    } else if (strcmp(param, "BackhaulAKMsAllowed") == 0) {
        dm_ctrl->fill_bss_akms_allowed(dm, bi, true, val_str, sizeof(val_str));
        rc = dm_ctrl->raw_data_set(p_data, val_str);
    } else if (strcmp(param, "QMDescriptor") == 0) {
        //rc = dm_ctrl->raw_data_set(p_data, bi->);
    } else if (strcmp(param, "STANumberOfEntries") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, bi->numberofsta);
    } else if (strcmp(param, "LinkRemovalImminent") == 0) {
        //rc = dm_ctrl->raw_data_set(p_data, bi->);
    } else if (strcmp(param, "FronthaulSuiteSelector") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, 0U);
    } else if (strcmp(param, "BackhaulSuiteSelector") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, 0U);
    } else {
        em_printfout("Invalid param: %s\n", param);
        rc = bus_error_invalid_input;
    }

    return rc;
}

int invoke(const char *event, bool no_pdata)
{
    raw_data_t raw;
    memset(&raw, 0, sizeof(raw));
    bus_user_data_t ud;
    return (int)g_ctrl.m_data_model.bss_get_inner(const_cast<char *>(event), no_pdata ? NULL : &raw, &ud);
}

} /* namespace bgi */
