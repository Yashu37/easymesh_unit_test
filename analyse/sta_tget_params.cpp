/*
 * HANDLER: sta_tget_params
 *
 * Function copied (fix 1 applied, start fix n / end fix n markers) from unified-wifi-mesh src/ctrl/dm_easy_mesh_ctrl.cpp
 * (develop @ 1ba9529), dm_easy_mesh_ctrl_t::sta_tget_params. Local arrays: ht_caps_str[32],
 * vht_caps_str[32], wifi6_name[128] (snprintf bounded); the read
 * em_crypto_t::base64_encode(si->frame_body, si->frame_body_len) (frame_body[EM_MAX_FRAME_BODY_LEN = 512],
 * the length is a data-model value that the frame-parsing code stores unclamped).
 * Scaffolding: one data model whose STA map holds the STAs of stp::sta_spec_t. Separate functions are stubs:
 * dm_sta_t::decode_sta_capability (no-op; in the live flow it walks the same frame_body up to
 * frame_body_len), get_sta_ht_caps_str / get_sta_vht_caps_str (copy the text), sta_wifi6_cap_value (true for
 * every even member), base64_encode (standard base64); property_append_tail records "idx:name=value".
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <string>
#include <type_traits>
#include "sta_tget_params.h"

namespace stp {

char g_rec[262144];
int g_rows = 0;
dm_easy_mesh_t *g_dm = NULL;
static bus_data_prop_t g_dummy_prop;
static void rec(unsigned int idx, const char *name, const char *val)
{
    size_t l = strlen(g_rec);
    if (l + 700 > sizeof(g_rec)) return;
    snprintf(g_rec + l, sizeof(g_rec) - l, "%u:%.200s=%.400s\n", idx, name, val);
    if (!strcmp(name, "MACAddress")) g_rows++;
}

void *hash_map_get_first(sta_map_t *m) { return (m && m->n) ? m->p[0] : NULL; }
void *hash_map_get_next(sta_map_t *m, void *cur)
{ for (int i = 0; i < m->n; i++) if (m->p[i] == cur) return i + 1 < m->n ? m->p[i + 1] : NULL; return NULL; }

class em_crypto_t {
public:
    static std::string base64_encode(const uint8_t *in, size_t len)
    {   static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string o; size_t i = 0;
        for (; i + 2 < len; i += 3) { uint32_t v = (in[i] << 16) | (in[i+1] << 8) | in[i+2];
            o += t[v >> 18]; o += t[(v >> 12) & 63]; o += t[(v >> 6) & 63]; o += t[v & 63]; }
        if (len - i == 1) { uint32_t v = in[i] << 16; o += t[v >> 18]; o += t[(v >> 12) & 63]; o += "=="; }
        else if (len - i == 2) { uint32_t v = (in[i] << 16) | (in[i+1] << 8); o += t[v >> 18]; o += t[(v >> 12) & 63]; o += t[(v >> 6) & 63]; o += '='; }
        return o; }
};

static const char *sta_wifi6_cap_members[] = {
    "HE160", "HE8080", "MCSNSS", "SUBeamformer", "SUBeamformee",
    "MUBeamformer", "Beamformee80orLess", "BeamformeeAbove80", "ULMUMIMO",
    "ULOFDMA", "DLOFDMA", "MaxDLMUMIMO", "MaxULMUMIMO", "MaxDLOFDMA",
    "MaxULOFDMA", "RTS", "MURTS", "MultiBSSID", "MUEDCA", "TWTRequestor",
    "TWTResponder", "SpatialReuse", "AnticipatedChannelUsage",
};

class dm_easy_mesh_ctrl_t {
public:
    char *get_sta_ht_caps_str(char *hex, char *buf, size_t n) { snprintf(buf, n, "%s", hex); return buf; }
    char *get_sta_vht_caps_str(char *hex, char *buf, size_t n) { snprintf(buf, n, "%s", hex); return buf; }
    bool sta_wifi6_cap_value(em_sta_info_t *si, const char *param, bool *out)
    { (void)si; for (unsigned i = 0; i < sizeof(sta_wifi6_cap_members) / sizeof(sta_wifi6_cap_members[0]); i++)
        if (!strcmp(param, sta_wifi6_cap_members[i])) { *out = (i % 2 == 0); return true; }
      return false; }
    void property_append_tail(bus_data_prop_t **prop, const char *root, unsigned int idx, const char *name, const char *v)
    { (void)root; if (!*prop) *prop = &g_dummy_prop; rec(idx, name, v ? v : "(null)"); }
    void property_append_tail(bus_data_prop_t **prop, const char *root, unsigned int idx, const char *name, const unsigned char *mac)
    { char s[18]; (void)root; if (!*prop) *prop = &g_dummy_prop; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); rec(idx, name, s); }
    template <typename T>
    typename std::enable_if<std::is_arithmetic<T>::value || std::is_enum<T>::value>::type
    property_append_tail(bus_data_prop_t **prop, const char *root, unsigned int idx, const char *name, T v)
    { char s[32]; (void)root; if (!*prop) *prop = &g_dummy_prop; snprintf(s, sizeof(s), "%lld", (long long)v); rec(idx, name, s); }
    bus_error_t sta_tget_params(dm_easy_mesh_t *dm, const char *root, em_bss_info_t *bi, bus_data_prop_t **property);
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
bus_error_t dm_easy_mesh_ctrl_t::sta_tget_params(dm_easy_mesh_t *dm, const char *root, em_bss_info_t *bi, bus_data_prop_t **property)
{
    bus_error_t rc = bus_error_success;

    unsigned int idx = 0;
    dm_easy_mesh_ctrl_t *dm_ctrl = em_ctrl_t::get_em_ctrl_instance()->get_dm_ctrl();
    dm_sta_t *sta = static_cast<dm_sta_t *> (hash_map_get_first(dm->m_sta_map));
    while (sta != NULL) {
        em_sta_info_t *si = sta->get_sta_info();
        if (si->associated == 0 ||
            memcmp(bi->bssid.mac, si->bssid, sizeof(si->bssid)) != 0) {
            sta = static_cast<dm_sta_t *> (hash_map_get_next(dm->m_sta_map, sta));
            continue;
        }
        ++idx;

        /* Derived capability fields; decode before reading (see sta_get_inner). */
        dm_sta_t::decode_sta_capability(sta);

        char ht_caps_str[32] = {0};
        char vht_caps_str[32] = {0};
        dm_ctrl->get_sta_ht_caps_str(si->ht_cap, ht_caps_str, sizeof(ht_caps_str));
        dm_ctrl->get_sta_vht_caps_str(si->vht_cap, vht_caps_str, sizeof(vht_caps_str));

/* start fix 1 */
        unsigned int frame_body_len = si->frame_body_len;
        if (frame_body_len > EM_MAX_FRAME_BODY_LEN) {
            frame_body_len = EM_MAX_FRAME_BODY_LEN;
        }
/* end fix 1 */
        std::string client_caps_b64;
        if (frame_body_len > 0) {
            client_caps_b64 = em_crypto_t::base64_encode(si->frame_body, frame_body_len);
        }

        dm_ctrl->property_append_tail(property, root, idx, "MACAddress", si->id);
        dm_ctrl->property_append_tail(property, root, idx, "HTCapabilities", ht_caps_str);
        dm_ctrl->property_append_tail(property, root, idx, "VHTCapabilities", vht_caps_str);
        dm_ctrl->property_append_tail(property, root, idx, "ClientCapabilities", client_caps_b64.c_str());

        for (unsigned int wi = 0; wi < sizeof(sta_wifi6_cap_members) / sizeof(sta_wifi6_cap_members[0]); wi++) {
            bool wifi6_val = false;
            em_long_string_t wifi6_name;
            (void)dm_ctrl->sta_wifi6_cap_value(si, sta_wifi6_cap_members[wi], &wifi6_val);
            snprintf(wifi6_name, sizeof(wifi6_name), "WiFi6Capabilities.%s", sta_wifi6_cap_members[wi]);
            dm_ctrl->property_append_tail(property, root, idx, wifi6_name, wifi6_val);
        }
        dm_ctrl->property_append_tail(property, root, idx, "LastDataDownlinkRate", si->last_dl_rate);
        dm_ctrl->property_append_tail(property, root, idx, "LastDataUplinkRate", si->last_ul_rate);
        dm_ctrl->property_append_tail(property, root, idx, "UtilizationReceive", si->util_rx);
        dm_ctrl->property_append_tail(property, root, idx, "UtilizationTransmit", si->util_tx);
        dm_ctrl->property_append_tail(property, root, idx, "EstMACDataRateDownlink", si->est_dl_rate);
        dm_ctrl->property_append_tail(property, root, idx, "EstMACDataRateUplink", si->est_ul_rate);
        dm_ctrl->property_append_tail(property, root, idx, "SignalStrength", static_cast<int32_t> (si->rcpi));
        dm_ctrl->property_append_tail(property, root, idx, "LastConnectTime", si->last_conn_time);
        dm_ctrl->property_append_tail(property, root, idx, "BytesSent", si->bytes_tx);
        dm_ctrl->property_append_tail(property, root, idx, "BytesReceived", si->bytes_rx);
        dm_ctrl->property_append_tail(property, root, idx, "PacketsSent", si->pkts_tx);
        dm_ctrl->property_append_tail(property, root, idx, "PacketsReceived", si->pkts_rx);
        dm_ctrl->property_append_tail(property, root, idx, "ErrorsSent", si->errors_tx);
        dm_ctrl->property_append_tail(property, root, idx, "ErrorsReceived", si->errors_rx);
        dm_ctrl->property_append_tail(property, root, idx, "RetransCount", si->retrans_count);
        dm_ctrl->property_append_tail(property, root, idx, "IPV4Address", "");
        dm_ctrl->property_append_tail(property, root, idx, "IPV6Address", "");
        dm_ctrl->property_append_tail(property, root, idx, "Hostname", "");
        dm_ctrl->property_append_tail(property, root, idx, "PairwiseAKM", 0U);
        dm_ctrl->property_append_tail(property, root, idx, "PairwiseCipher", 0U);
        dm_ctrl->property_append_tail(property, root, idx, "RSNCapabilities", 0U);
        sta = static_cast<dm_sta_t *> (hash_map_get_next(dm->m_sta_map, sta));
    }

    return rc;
}

int invoke(const char *root)
{
    bus_data_prop_t *prop = NULL;
    em_bss_info_t bi;
    memset(&bi, 0, sizeof(bi));
    unsigned char m[6] = {2, 0, 0, 0, 0, 1};
    memcpy(bi.bssid.mac, m, 6);
    return (int)g_ctrl.m_data_model.sta_tget_params(g_dm, root, &bi, &prop);
}

} /* namespace stp */
