/*
 * HANDLER: handle_failed_conn_msg
 *
 * Function copied VERBATIM from unified-wifi-mesh src/ctrl/em_ctrl.cpp (develop @ 1ba9529),
 * em_ctrl_t::handle_failed_conn_msg. It parses the TLVs of a Failed Connection message after
 * em_msg_t(...).validate(); em_msg_t::validate() and em_msg_t::failed_conn() (src/em/em_msg.cpp) are
 * copied verbatim too (the real validation decides which malformed messages reach the loop; it only
 * checks the FIRST TLV of each type). Local arrays: errors[64], bssid[6], sta_mac[6], timestamp[64],
 * bssid_str / sta_str[18]; the reads memcpy(bssid, tlv->value, 6) / memcpy(sta_mac, tlv->value, 6) /
 * sc->status_code of every TLV found in the buffer.
 * Scaffolding: the message is an exactly-sized copy in hfc::msg_store (runner poisons around it);
 * the bus descriptor records the published JSON; cJSON is the real library.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>
#include <string>
#include "handle_failed_conn_msg.h"

namespace hfc {

int g_npub = 0;
char g_pub[2048];
bool g_no_desc = false, g_pub_fail = false;
static wifi_bus_desc_t g_desc;

static int pub_fn(void *hdl, const char *name, raw_data_t *data)
{
    (void)hdl; (void)name;
    g_npub++;
    const char *s = (const char *)data->raw_data.bytes;
    size_t o = 0;
    for (size_t i = 0; s[i] && o + 1 < sizeof(g_pub); i++) if (s[i] != '\n' && s[i] != '\t' && s[i] != ' ') g_pub[o++] = s[i];
    g_pub[o] = '\0';
    return g_pub_fail ? 1 : 0;
}

class dm_easy_mesh_t {
public:
    static void macbytes_to_string(unsigned char *mac, char *string)
    { snprintf(string, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); }
};
class em_data_model_t { public: void *get_bus_hdl() { return NULL; } };

/* --- copied verbatim from src/em/em_msg.cpp (class cut down to the members these use) --- */
class em_msg_t {
    em_msg_type_t m_type;
    em_profile_type_t m_profile;
    unsigned int m_num_tlv;
    em_tlv_member_t m_tlv_member[EM_MAX_TLV_MEMBERS];
    unsigned int m_num_errors;
    em_short_string_t m_errors[EM_MAX_TLV_MEMBERS];
    unsigned char *m_buff;
    unsigned int m_len;
public:
    em_msg_t(em_msg_type_t type, em_profile_type_t profile, unsigned char *tlvs, unsigned int len)
    {   m_type = type; m_profile = profile; m_num_tlv = 0; m_buff = tlvs; m_len = len; m_num_errors = 0;
        if (type == em_msg_type_failed_conn) failed_conn(); }
    unsigned int validate(char *errors[]);
    void failed_conn();
};
unsigned int em_msg_t::validate(char *errors[])
{
    em_tlv_t *tlv;
    unsigned int i, len;
    bool validation = true;

    unsigned int header_sz = static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    if (m_len < header_sz) {
        em_printfout("Error: Malformed msg");
        return false;
    }
    tlv = reinterpret_cast<em_tlv_t *> (m_buff + header_sz);
    len = m_len - header_sz;
    while ((len >= sizeof(em_tlv_t)) && (tlv->type != em_tlv_type_eom)) {
        unsigned int tlv_len = static_cast<unsigned int> (sizeof(em_tlv_t) + ntohs(tlv->len));
        if (len < tlv_len) {
            em_printfout("Error: Malformed TLV");
            return false;
        }
        len -= tlv_len;
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *>(tlv) + tlv_len);
    }
    if (len < sizeof(em_tlv_t)) {   // no room left for an EOM
        em_printfout("Error: Missing EOM TLV");
        return false;
    }

    for (i = 0; i < m_num_tlv; i++) {
        tlv = reinterpret_cast<em_tlv_t *> (m_buff + header_sz);
        len = m_len - header_sz;
        while ((len >= sizeof(em_tlv_t)) && (tlv->type != em_tlv_type_eom)) {
            unsigned int tlv_len = static_cast<unsigned int> (sizeof(em_tlv_t) + ntohs(tlv->len));
            if (tlv->type == m_tlv_member[i].m_type) {
                m_tlv_member[i].m_present = true;
                break;
            }
            len -= tlv_len;
            tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *>(tlv) + tlv_len);
        }

        if ((m_tlv_member[i].m_requirement == mandatory) &&((m_tlv_member[i].m_present == false)||((sizeof(em_tlv_t) + htons(tlv->len)) < static_cast<size_t> (m_tlv_member[i].m_tlv_length)))) {
            strncpy(m_errors[m_num_errors], m_tlv_member[i].m_spec, sizeof(m_errors[m_num_errors]));
            m_num_errors++;
            errors[m_num_errors - 1] = m_errors[m_num_errors - 1];
            validation = false;
        }

        if ((m_tlv_member[i].m_requirement == bad) && (m_tlv_member[i].m_present == true)) {
            strncpy(m_errors[m_num_errors], m_tlv_member[i].m_spec, sizeof(m_errors[m_num_errors]));
            m_num_errors++;
            errors[m_num_errors - 1] = m_errors[m_num_errors - 1];
            //printf("%s:%d; TLV type: 0x%04x Length: %d, presence validation error, profile: %d\n", __func__, __LINE__, 
            //tlv->type, htons(tlv->len), m_profile);
            validation = false;
        }
    }

    if (validation == false) {
        for (i = 0; i < EM_MAX_TLV_MEMBERS; i++) {
            if (errors[i] != NULL) {
                printf("Failed TLV [%d]: %s\n",(i+1),errors[i]);
            }
        }
    }

    return validation;
}

void em_msg_t::failed_conn()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_bssid, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.74 of Wi-Fi Easy Mesh 5.0", 9);       
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_sta_mac_addr, mandatory, "17.2.23 of Wi-Fi Easy Mesh 5.0", 9);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_status_code, mandatory, "17.2.63 of Wi-Fi Easy Mesh 5.0", 5);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_reason_code, optional, "17.2.64 of Wi-Fi Easy Mesh 5.0", 5);
}

class em_ctrl_t {
public:
    em_data_model_t m_data_model;
    wifi_bus_desc_t *get_bus_descriptor() { return g_no_desc ? NULL : &g_desc; }
    void handle_failed_conn_msg(unsigned char *data, unsigned int len);
};
static em_ctrl_t g_ctrl;

/* --- copied verbatim from src/ctrl/em_ctrl.cpp --- */
void em_ctrl_t::handle_failed_conn_msg(unsigned char *data, unsigned int len)
{
    char *errors[EM_MAX_TLV_MEMBERS] = {0};

    if (em_msg_t(em_msg_type_failed_conn, em_profile_type_3, data, len).validate(errors) == 0) {
        em_printfout("Failed Connection message validation failed");
        return;
    }

    unsigned int hdr_size = static_cast<unsigned int>(sizeof(em_raw_hdr_t)) + static_cast<unsigned int>(sizeof(em_cmdu_t));
    if (len <= hdr_size) {
        em_printfout("Failed Connection message too short");
        return;
    }
    unsigned char *tmp = data + hdr_size;
    unsigned int remaining = len - hdr_size;
    mac_address_t bssid = {0};
    mac_address_t sta_mac = {0};
    unsigned short status_code = 0;
    unsigned short reason_code = 0;
    bool has_bssid = false, has_sta = false, has_status = false;

    while (remaining >= sizeof(em_tlv_t)) {
        em_tlv_t *tlv = reinterpret_cast<em_tlv_t *>(tmp);
        unsigned short tlv_len = ntohs(tlv->len);

        if (tlv->type == em_tlv_type_eom) {
            break;
        }
        if (remaining < sizeof(em_tlv_t) + tlv_len) {
            break;
        }

        switch (tlv->type) {
            case em_tlv_type_bssid:
                memcpy(bssid, tlv->value, sizeof(mac_address_t));
                has_bssid = true;
                break;
            case em_tlv_type_sta_mac_addr:
                memcpy(sta_mac, tlv->value, sizeof(mac_address_t));
                has_sta = true;
                break;
            case em_tlv_type_status_code: {
                em_status_code_t *sc = reinterpret_cast<em_status_code_t *>(tlv->value);
                status_code = ntohs(sc->status_code);
                has_status = true;
                break;
            }
            case em_tlv_type_reason_code: {
                if (tlv_len < sizeof(em_reason_code_t)) {
                    em_printfout("Failed Connection message malformed Reason Code TLV (len=%u)", static_cast<unsigned int>(tlv_len));
                    break;
                }
                em_reason_code_t *rc = reinterpret_cast<em_reason_code_t *>(tlv->value);
                reason_code = ntohs(rc->reason_code);
                break;
            }
            default:
                break;
        }

        tmp += sizeof(em_tlv_t) + tlv_len;
        remaining -= static_cast<unsigned int>(sizeof(em_tlv_t)) + tlv_len;
    }

    if (!has_bssid || !has_sta || !has_status) {
        em_printfout("Failed Connection message missing mandatory TLVs");
        return;
    }

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm_info;
    gmtime_r(&ts.tv_sec, &tm_info);
    char timestamp[MAX_TIMESTAMP_STRLEN];
    snprintf(timestamp, sizeof(timestamp), "%04d-%02d-%02dT%02d:%02d:%02dZ",
        tm_info.tm_year + 1900, tm_info.tm_mon + 1, tm_info.tm_mday,
        tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec);

    mac_addr_str_t bssid_str, sta_str;
    dm_easy_mesh_t::macbytes_to_string(bssid, bssid_str);
    dm_easy_mesh_t::macbytes_to_string(sta_mac, sta_str);

    cJSON *obj = cJSON_CreateObject();
    if (obj == nullptr) {
        em_printfout("Failed to allocate JSON object for FailedConnectionEvent");
        return;
    }

    cJSON_AddStringToObject(obj, "BSSID", bssid_str);
    cJSON_AddStringToObject(obj, "MACAddress", sta_str);
    cJSON_AddNumberToObject(obj, "StatusCode", status_code);
    cJSON_AddNumberToObject(obj, "ReasonCode", reason_code);
    cJSON_AddStringToObject(obj, "TimeStamp", timestamp);

    char *str = cJSON_Print(obj);
    cJSON_Delete(obj);

    if (str == nullptr) {
        em_printfout("Failed to serialize FailedConnectionEvent JSON");
        return;
    }

    wifi_bus_desc_t *desc = get_bus_descriptor();
    if (desc == nullptr) {
        em_printfout("Bus descriptor is null");
        free(str);
        return;
    }

    raw_data_t raw;
    memset(&raw, 0, sizeof(raw));
    raw.data_type = bus_data_type_string;
    raw.raw_data.bytes = reinterpret_cast<unsigned char *>(str);
    raw.raw_data_len = static_cast<unsigned int>(strlen(str));

    if (desc->bus_event_publish_fn(m_data_model.get_bus_hdl(), DEVICE_WIFI_DATAELEMENTS_FAILED_CONNECTION, &raw) == 0) {
        em_printfout("FailedConnectionEvent published: bssid=%s sta=%s status=%u reason=%u",
            bssid_str, sta_str, status_code, reason_code);
    } else {
        em_printfout("FailedConnectionEvent publish failed");
    }

    free(str);
}

void invoke(void)
{
    g_desc.bus_event_publish_fn = pub_fn;
    g_ctrl.handle_failed_conn_msg(g_msg, g_len);
}

} /* namespace hfc */
