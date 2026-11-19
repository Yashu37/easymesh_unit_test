/*
 * HANDLER: sta_get_inner
 *
 * Function copied from unified-wifi-mesh src/ctrl/dm_easy_mesh_ctrl.cpp (develop @ 1ba9529),
 * dm_easy_mesh_ctrl_t::sta_get_inner (fixes 1-6 applied, start fix n / end fix n markers), with get_table_instance() and get_dm_sta(dm, bi, int) (same file). Local arrays:
 * instance[32], caps_str[32] (two of them); the array accesses dm->m_radio[radio_instance - 1] (EM_MAX_BANDS = 3),
 * dm->get_bss_info(i) for i < dm->m_num_bss (m_bss[EM_MAX_BSSS = 24]), name += sizeof(DATAELEMS_NETWORK) and the reads of
 * si->frame_body up to si->frame_body_len (decode_sta_capability, base64_encode; frame_body[EM_MAX_FRAME_BODY_LEN = 512]).
 * Scaffolding: one device 1 with 3 radios, a BSS list and a STA map; separate functions are stubs: decode_sta_capability
 * (stand-in that reads frame_body[0 .. frame_body_len) like the live decoder), get_sta_ht_caps_str / get_sta_vht_caps_str
 * (copy the text), sta_wifi6_cap_value (true for even member index). raw_data_set records the value it is given.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <string>
#include <type_traits>
#include "sta_get_inner.h"

namespace sgi {

char g_val[SGI_VAL_SZ];
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

/* start fix 3 */
    if (src == NULL) {
        return NULL;
    }
    src = strstr(src, ".");
    if (src == NULL) {
        return NULL;
    }
/* end fix 3 */
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

dm_sta_t* dm_easy_mesh_ctrl_t::get_dm_sta(dm_easy_mesh_t *dm, em_bss_info_t *bi, int instance)
{
    int scnt = 0;
    mac_addr_str_t bss_str, sta_str;

    dm_sta_t *sta = static_cast<dm_sta_t *> (hash_map_get_first(dm->m_sta_map));
    while (sta != NULL) {
        em_sta_info_t *si = sta->get_sta_info();
        dm_easy_mesh_t::macbytes_to_string(bi->bssid.mac, bss_str);
        dm_easy_mesh_t::macbytes_to_string(si->bssid, sta_str);
        em_printfout("Comparing bss:%s sta:%s", bss_str, sta_str);
        if (si->associated == 0 ||
            memcmp(bi->bssid.mac, si->bssid, sizeof(si->bssid)) != 0) {
            sta = static_cast<dm_sta_t *> (hash_map_get_next(dm->m_sta_map, sta));
            continue;
        }
        ++scnt;
        if (scnt == instance) {
            return sta;
        }
        sta = static_cast<dm_sta_t *> (hash_map_get_next(dm->m_sta_map, sta));
    }

    return NULL;
}

bus_error_t dm_easy_mesh_ctrl_t::sta_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    (void) user_data;
    const char *name = event_name;
    const char *param;
    unsigned int i = 0;
    int count = 0;
    char instance[MAX_INSTANCE_LEN] = { 0 };
    bool is_num;
    int radio_instance = 0, bss_instance = 0, sta_instance = 0;
    bus_error_t rc;

/* start fix 1 */
    if (name == NULL) {
        return bus_error_invalid_input;
    }
/* end fix 1 */
    param = strrchr(name, '.');
    if (param == NULL) {
        return bus_error_invalid_input;
    }
    ++param;

    dm_easy_mesh_ctrl_t *dm_ctrl = em_ctrl_t::get_em_ctrl_instance()->get_dm_ctrl();

    /* Extract device instance (numeric or alias) and find the dm object for
     * that device instance */
/* start fix 2 */
    if (strlen(name) < sizeof(DATAELEMS_NETWORK)) {
        return bus_error_invalid_input;
    }
/* end fix 2 */
    name += sizeof(DATAELEMS_NETWORK);
    name = dm_ctrl->get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
/* start fix 3 */
    if (name == NULL) {
        return bus_error_invalid_input;
    }
/* end fix 3 */
    dm_easy_mesh_t *dm = dm_ctrl->get_dm_easy_mesh(instance, is_num);
    if (dm == NULL) {
        printf("device not found\n");
        return bus_error_invalid_namespace;
    }

    name = dm_ctrl->get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
/* start fix 3 */
    if (name == NULL) {
        return bus_error_invalid_input;
    }
/* end fix 3 */
    radio_instance = is_num ? atoi(instance) : 0;
/* start fix 4 */
    if (radio_instance < 1 || radio_instance > EM_MAX_BANDS) {
        em_printfout("radio instance %d out of range", radio_instance);
        return bus_error_invalid_input;
    }
/* end fix 4 */
    dm_radio_t *radio = &dm->m_radio[radio_instance - 1];
    if (radio == NULL) {
        em_printfout("radio is NULL\n");
        return bus_error_invalid_input;
    }
    em_radio_info_t *ri = radio->get_radio_info();
    em_bss_info_t *bi;
    mac_addr_str_t  radio_str, bss_str;

    name = dm_ctrl->get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
/* start fix 3 */
    if (name == NULL) {
        return bus_error_invalid_input;
    }
/* end fix 3 */
    bss_instance = is_num ? atoi(instance) : 0;
/* start fix 5 */
    unsigned int num_bss = dm->m_num_bss > EM_MAX_BSSS ? EM_MAX_BSSS : dm->m_num_bss;
    for(i = 0; i < num_bss; i++) {
/* end fix 5 */
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

    name = dm_ctrl->get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
/* start fix 3 */
    if (name == NULL) {
        return bus_error_invalid_input;
    }
/* end fix 3 */
    sta_instance = is_num ? atoi(instance) : 0;
    dm_sta_t *sta = dm_ctrl->get_dm_sta(dm, bi, sta_instance);
    if (sta == NULL) {
        em_printfout("sta is NULL\n");
        return bus_error_invalid_input;
    }
    /* The capability fields are derived from the stored (re)assoc request frame
       body, not persisted with the station record; decode before reading. */
    em_sta_info_t *si = sta->get_sta_info();
/* start fix 6 */
    if (si->frame_body_len > EM_MAX_FRAME_BODY_LEN) {
        si->frame_body_len = EM_MAX_FRAME_BODY_LEN;
    }
/* end fix 6 */
    dm_sta_t::decode_sta_capability(sta);

    if (strcmp(param, "MACAddress") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, si->id);
    } else if (strcmp(param, "TimeStamp") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, si->timestamp);
    } else if (strcmp(param, "HTCapabilities") == 0) {
        char caps_str[32] = {0};
        dm_ctrl->get_sta_ht_caps_str(si->ht_cap, caps_str, sizeof(caps_str));
        rc = dm_ctrl->raw_data_set(p_data, caps_str);
    } else if (strcmp(param, "VHTCapabilities") == 0) {
        char caps_str[32] = {0};
        dm_ctrl->get_sta_vht_caps_str(si->vht_cap, caps_str, sizeof(caps_str));
        rc = dm_ctrl->raw_data_set(p_data, caps_str);
    } else if (strcmp(param, "ClientCapabilities") == 0) {
        /* TR-181: base64-encoded frame body of the last (Re)Association Request. */
        std::string caps_b64;
        if (si->frame_body_len > 0) {
            caps_b64 = em_crypto_t::base64_encode(si->frame_body, si->frame_body_len);
        }
        rc = dm_ctrl->raw_data_set(p_data, caps_b64.c_str());
    } else if (strcmp(param, "LastDataDownlinkRate") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, si->last_dl_rate);
    } else if (strcmp(param, "LastDataUplinkRate") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, si->last_ul_rate);
    } else if (strcmp(param, "UtilizationReceive") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, si->util_rx);
    } else if (strcmp(param, "UtilizationTransmit") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, si->util_tx);
    } else if (strcmp(param, "EstMACDataRateDownlink") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, si->est_dl_rate);
    } else if (strcmp(param, "EstMACDataRateUplink") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, si->est_ul_rate);
    } else if (strcmp(param, "SignalStrength") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, static_cast<int32_t> (si->rcpi));
    } else if (strcmp(param, "LastConnectTime") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, si->last_conn_time);
    } else if (strcmp(param, "BytesSent") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, si->bytes_tx);
    } else if (strcmp(param, "BytesReceived") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, si->bytes_rx);
    } else if (strcmp(param, "PacketsSent") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, si->pkts_tx);
    } else if (strcmp(param, "PacketsReceived") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, si->pkts_rx);
    } else if (strcmp(param, "ErrorsSent") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, si->errors_tx);
    } else if (strcmp(param, "ErrorsReceived") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, si->errors_rx);
    } else if (strcmp(param, "RetransCount") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, si->retrans_count);
    } else if (strcmp(param, "IPV4Address") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, "");
    } else if (strcmp(param, "IPV6Address") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, "");
    } else if (strcmp(param, "Hostname") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, "");
    } else if (strcmp(param, "PairwiseAKM") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, 0U);
    } else if (strcmp(param, "PairwiseCipher") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, 0U);
    } else if (strcmp(param, "RSNCapabilities") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, 0U);
    } else {
        bool wifi6_val = false;
        if (dm_ctrl->sta_wifi6_cap_value(si, param, &wifi6_val)) {
            rc = dm_ctrl->raw_data_set(p_data, wifi6_val);
        } else {
            em_printfout("Invalid param: %s\n", param);
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
    return (int)g_ctrl.m_data_model.sta_get_inner(const_cast<char *>(event), no_pdata ? NULL : &raw, &ud);
}

} /* namespace sgi */
