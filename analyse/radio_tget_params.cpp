/*
 * HANDLER: radio_tget_params
 *
 * Function copied (fixes 1-2 applied, start fix n / end fix n markers) from unified-wifi-mesh src/ctrl/dm_easy_mesh_ctrl.cpp
 * (develop @ 1ba9529), dm_easy_mesh_ctrl_t::radio_tget_params, with get_supported_standards_str(),
 * get_ht_caps_str() and get_vht_caps_str() (same file) and dm_easy_mesh_t::get_radio() /
 * get_radio_cap(mac) (src/dm/dm_easy_mesh.cpp). Local arrays: path[512], caps_str[32],
 * supported_standards[64], id_str[16]; loops over dm->get_num_op_class() (m_op_class[64]) and
 * dm_easy_mesh_t::get_radio_cap() over m_num_radios (m_radio_cap[3]).
 * Scaffolding: one data model described by rtp::test_case_t; property_append_tail records
 * "idx:name=value"; the sub handlers (curops / capops / wf6ap / wf7ap / bss _tget_params) and
 * get_dm_bh_sta are separate functions and only record their path / result.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <string>
#include <type_traits>
#include "radio_tget_params.h"

namespace rtp {

char g_rec[65536];
int g_ids = 0;
dm_easy_mesh_t *g_dm = NULL;
static dm_sta_t g_sta;
static bool g_has_bh = false;
static bus_data_prop_t g_dummy_prop;
static void rec(unsigned int idx, const char *name, const char *val)
{
    size_t l = strlen(g_rec);
    if (l + 512 > sizeof(g_rec)) return;
    snprintf(g_rec + l, sizeof(g_rec) - l, "%u:%.200s=%.200s\n", idx, name, val);
    if (!strcmp(name, "ID")) g_ids++;
}

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

class dm_easy_mesh_ctrl_t {
public:
    char *get_supported_standards_str(wifi_ieee80211Variant_t variant, char *buf, size_t buf_size);
    char *get_ht_caps_str(em_ap_ht_cap_t *ht, char *buf, size_t buf_len);
    char *get_vht_caps_str(em_ap_vht_cap_t *vht, char *buf, size_t buf_len);
    dm_sta_t *get_dm_bh_sta(dm_easy_mesh_t *dm, dm_radio_t *radio) { (void)dm; (void)radio; return g_has_bh ? &g_sta : NULL; }
    void curops_tget_params(dm_easy_mesh_t *dm, const char *path, em_radio_info_t *ri, bus_data_prop_t **prop) { (void)dm; (void)ri; (void)prop; rec(0, "curops_path", path); }
    void capops_tget_params(dm_easy_mesh_t *dm, const char *path, em_radio_info_t *ri, bus_data_prop_t **prop) { (void)dm; (void)ri; (void)prop; rec(0, "capops_path", path); }
    void wf6ap_tget_params(dm_easy_mesh_t *dm, const char *path, em_radio_info_t *ri, bus_data_prop_t **prop, unsigned int idx) { (void)dm; (void)ri; (void)prop; rec(idx, "wf6ap_path", path); }
    void wf7ap_tget_params(dm_easy_mesh_t *dm, const char *path, em_radio_info_t *ri, bus_data_prop_t **prop, unsigned int idx) { (void)dm; (void)ri; (void)prop; rec(idx, "wf7ap_path", path); }
    void bss_tget_params(dm_easy_mesh_t *dm, const char *path, em_radio_info_t *ri, bus_data_prop_t **prop) { (void)dm; (void)ri; (void)prop; rec(0, "bss_path", path); }
    void property_append_tail(bus_data_prop_t **prop, const char *root, unsigned int idx, const char *name, const char *v)
    { (void)root; if (!*prop) *prop = &g_dummy_prop; rec(idx, name, v ? v : "(null)"); }
    void property_append_tail(bus_data_prop_t **prop, const char *root, unsigned int idx, const char *name, const unsigned char *mac)
    { char s[18]; (void)root; if (!*prop) *prop = &g_dummy_prop; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); rec(idx, name, s); }
    template <typename T>
    typename std::enable_if<std::is_arithmetic<T>::value || std::is_enum<T>::value>::type
    property_append_tail(bus_data_prop_t **prop, const char *root, unsigned int idx, const char *name, T v)
    { char s[32]; (void)root; if (!*prop) *prop = &g_dummy_prop; snprintf(s, sizeof(s), "%lld", (long long)v); rec(idx, name, s); }
    bus_error_t radio_tget_params(dm_easy_mesh_t *dm, const char *root, bus_data_prop_t **property);
};
class em_ctrl_t {
public:
    dm_easy_mesh_ctrl_t m_data_model;
    static em_ctrl_t *get_em_ctrl_instance();
    dm_easy_mesh_ctrl_t *get_dm_ctrl() { return &m_data_model; }
};
static em_ctrl_t g_ctrl;
em_ctrl_t *em_ctrl_t::get_em_ctrl_instance() { return &g_ctrl; }

/* --- copied verbatim from src/dm/dm_easy_mesh.cpp --- */
dm_radio_t *dm_easy_mesh_t::get_radio(unsigned int index)
{
	if (index < EM_MAX_BANDS) {
		return &m_radio[index];
	} else {
		return NULL;
	}
}

dm_radio_cap_t *dm_easy_mesh_t::get_radio_cap(mac_address_t mac)
{
    unsigned int i = 0;

/* start fix 2 */
    for (i = 0; i < m_num_radios && i < EM_MAX_BANDS; i++) {
/* end fix 2 */
        if (memcmp(m_radio_cap[i].m_radio_cap_info.ruid.mac, mac, sizeof(mac_address_t)) == 0) {
            return &m_radio_cap[i];
        }
    }
    return NULL;
}

/* --- copied verbatim from src/ctrl/dm_easy_mesh_ctrl.cpp --- */
char* dm_easy_mesh_ctrl_t::get_supported_standards_str(wifi_ieee80211Variant_t variant, char *buf, size_t buf_size)
{
    if (!buf || buf_size == 0)
        return nullptr;

    buf[0] = '\0';
    size_t len = 0;

    auto append = [&](const char* s) {
        size_t slen = strlen(s);
        size_t needed = (len == 0) ? slen : (slen + 1);
        if (len + needed + 1 > buf_size) return;
        if (len != 0) {
            buf[len++] = ',';
        }
        memcpy(buf + len, s, slen);
        len += slen;
        buf[len] = '\0';
    };

    if (variant & WIFI_80211_VARIANT_A)  append("a");
    if (variant & WIFI_80211_VARIANT_B)  append("b");
    if (variant & WIFI_80211_VARIANT_G)  append("g");
    if (variant & WIFI_80211_VARIANT_N)  append("n");
    if (variant & WIFI_80211_VARIANT_AC) append("ac");
    if (variant & WIFI_80211_VARIANT_AX) append("ax");
    if (variant & WIFI_80211_VARIANT_BE) append("be");
    if (variant & WIFI_80211_VARIANT_BN) append("bn");

    return buf;
}

char* dm_easy_mesh_ctrl_t::get_ht_caps_str(em_ap_ht_cap_t *ht, char *buf, size_t buf_len)
{
    uint8_t data;

    uint8_t tx_streams = ht->max_sprt_tx_streams ? ht->max_sprt_tx_streams - 1 : 0;
    uint8_t rx_streams = ht->max_sprt_rx_streams ? ht->max_sprt_rx_streams - 1 : 0;

    /* Prepare data */
    data  = static_cast<uint8_t>((tx_streams) << 6);
    data |= static_cast<uint8_t>((rx_streams) << 4);
    data |= static_cast<uint8_t>(ht->gi_sprt_20mhz << 3);
    data |= static_cast<uint8_t>(ht->gi_sprt_40mhz << 2);
    data |= static_cast<uint8_t>(ht->ht_sprt_40mhz << 1);

    /* HTCapabilities is a base64 encoded octet string per TR-181 DataElements. */
    std::string encoded = em_crypto_t::base64_encode(&data, sizeof(data));
    snprintf(buf, buf_len, "%s", encoded.c_str());
    return buf;
}

char* dm_easy_mesh_ctrl_t::get_vht_caps_str(em_ap_vht_cap_t *vht, char *buf, size_t buf_len)
{
    uint8_t data[6] = {0};

    uint8_t tx_streams = vht->max_sprt_tx_streams ? vht->max_sprt_tx_streams - 1 : 0;
    uint8_t rx_streams = vht->max_sprt_rx_streams ? vht->max_sprt_rx_streams - 1 : 0;

    /* Prepare data */
    data[0] = static_cast<uint8_t>(vht->sprt_tx_mcs >> 8);
    data[1] = static_cast<uint8_t>(vht->sprt_tx_mcs & 0xff);
    data[2] = static_cast<uint8_t>(vht->sprt_rx_mcs >> 8);
    data[3] = static_cast<uint8_t>(vht->sprt_rx_mcs & 0xff);
    data[4] = static_cast<uint8_t>(tx_streams << 5);
    data[4] |= static_cast<uint8_t>(rx_streams << 2);
    data[4] |= static_cast<uint8_t>(vht->gi_sprt_80mhz << 1);
    data[4] |= static_cast<uint8_t>(vht->gi_sprt_160mhz);
    data[5] = static_cast<uint8_t>(vht->sprt_80_80_mhz << 7);
    data[5] |= static_cast<uint8_t>(vht->sprt_160mhz << 6);
    data[5] |= static_cast<uint8_t>(vht->su_beamformer_cap << 5);
    data[5] |= static_cast<uint8_t>(vht->mu_beamformer_cap << 4);

    /* VHTCapabilities is a base64 encoded octet string per TR-181 DataElements. */
    std::string encoded = em_crypto_t::base64_encode(data, sizeof(data));
    snprintf(buf, buf_len, "%s", encoded.c_str());

    return buf;
}

bus_error_t dm_easy_mesh_ctrl_t::radio_tget_params(dm_easy_mesh_t *dm, const char *root, bus_data_prop_t **property)
{
    char path[512];
    char caps_str[MAX_CAPS_STR_LEN] = { 0 };
    char supported_standards[MAX_STDLEN] = { 0 };
    bus_error_t rc = bus_error_success;
    dm_easy_mesh_ctrl_t *dm_ctrl = em_ctrl_t::get_em_ctrl_instance()->get_dm_ctrl();

    for (unsigned int idx = 1; idx <= dm->get_num_radios(); idx++) {
        dm_radio_t *radio = dm->get_radio(idx - 1);
        if (radio == NULL) {
            continue;
        }
        em_radio_info_t *ri = radio->get_radio_info();
        /* Radio ID is the base64 encoded RUID (MAC) per TR-181 DataElements. */
        char id_str[16] = { 0 };
        std::string id_b64 = em_crypto_t::base64_encode(ri->id.ruid, sizeof(ri->id.ruid));
        snprintf(id_str, sizeof(id_str), "%s", id_b64.c_str());
        dm_ctrl->property_append_tail(property, root, idx, "ID", id_str);
        dm_ctrl->property_append_tail(property, root, idx, "Enabled", ri->enabled);
        dm_ctrl->property_append_tail(property, root, idx, "Noise", static_cast<unsigned int> (ri->noise));
        dm_ctrl->property_append_tail(property, root, idx, "Utilization", static_cast<unsigned int> (ri->utilization));
        dm_ctrl->property_append_tail(property, root, idx, "Transmit", static_cast<unsigned int> (ri->transmit));
        dm_ctrl->property_append_tail(property, root, idx, "ReceiveSelf", static_cast<unsigned int> (ri->receive_self));
        dm_ctrl->property_append_tail(property, root, idx, "ReceiveOther", static_cast<unsigned int> (ri->receive_other));
        dm_ctrl->property_append_tail(property, root, idx, "ChipsetVendor", ri->chip_vendor);
        dm_ctrl->property_append_tail(property, root, idx, "X_AIRTIES_Temperature", ri->radio_temp);
        unsigned int curop_count = 0;
/* start fix 1 */
        unsigned int num_opclass = dm->get_num_op_class();
        if (num_opclass > EM_MAX_OPCLASS) {
            num_opclass = EM_MAX_OPCLASS;
        }
/* end fix 1 */
        for (unsigned int i = 0; i < num_opclass; i++) {
            dm_op_class_t *op_class = dm->get_op_class(i);
            if (op_class == NULL) {
                continue;
            }
            em_op_class_info_t *oci = op_class->get_op_class_info();
            if (oci->id.type != em_op_class_type_current) {
                continue;
            }
            if (memcmp(ri->id.ruid, oci->id.ruid, sizeof(oci->id.ruid)) != 0) {
                continue;
            }
            curop_count++;
        }
        dm_ctrl->property_append_tail(property, root, idx, "CurrentOperatingClassProfileNumberOfEntries", curop_count);
        dm_ctrl->property_append_tail(property, root, idx, "BSSNumberOfEntries", ri->number_of_bss);

        dm_sta_t *bh_sta = dm_ctrl->get_dm_bh_sta(dm, radio);
        if (bh_sta == NULL) {
            dm_ctrl->property_append_tail(property, root, idx, "BackhaulSta.MACAddress", "");
        } else {
            em_sta_info_t *si = bh_sta->get_sta_info();
            if (ri->number_of_bss != 4) { /* Very nasty hack, only report backhaulsta for radio with 4 bss */
                dm_ctrl->property_append_tail(property, root, idx, "BackhaulSta.MACAddress", "");
            } else {
                dm_ctrl->property_append_tail(property, root, idx, "BackhaulSta.MACAddress", si->id);
            }
        }

        unsigned int capop_count = 0;
/* start fix 1 */
        num_opclass = dm->get_num_op_class();
        if (num_opclass > EM_MAX_OPCLASS) {
            num_opclass = EM_MAX_OPCLASS;
        }
/* end fix 1 */
        for (unsigned int i = 0; i < num_opclass; i++) {
            dm_op_class_t *op_class = dm->get_op_class(i);
            if (op_class == NULL) {
                continue;
            }
            em_op_class_info_t *oci = op_class->get_op_class_info();
            if (oci->id.type != em_op_class_type_capability) {
                continue;
            }
            if (memcmp(ri->id.ruid, oci->id.ruid, sizeof(oci->id.ruid)) != 0) {
                continue;
            }
            capop_count++;
        }

        dm_radio_cap_t *radio_cap = dm->get_radio_cap(ri->id.ruid);
        if (radio_cap != NULL) {
            em_radio_cap_info_t *rci = radio_cap->get_radio_cap_info();
            dm_ctrl->get_supported_standards_str(rci->mode, supported_standards, sizeof(supported_standards));
            dm_ctrl->property_append_tail(property, root, idx, "X_AIRTIES_OperatingStandards", supported_standards);
            dm_ctrl->get_ht_caps_str(&rci->ht_cap, caps_str, sizeof(caps_str));
            dm_ctrl->property_append_tail(property, root, idx, "Capabilities.HTCapabilities", caps_str);
            dm_ctrl->get_vht_caps_str(&rci->vht_cap, caps_str, sizeof(caps_str));
            dm_ctrl->property_append_tail(property, root, idx, "Capabilities.VHTCapabilities", caps_str);
            dm_ctrl->property_append_tail(property, root, idx, "Capabilities.CapableOperatingClassProfileNumberOfEntries", capop_count);
        } else {
            dm_ctrl->property_append_tail(property, root, idx, "Capabilities.HTCapabilities", "");
            dm_ctrl->property_append_tail(property, root, idx, "Capabilities.VHTCapabilities", "");
            dm_ctrl->property_append_tail(property, root, idx, "Capabilities.CapableOperatingClassProfileNumberOfEntries", capop_count);
        }

        snprintf(path, sizeof(path) - 1, "%s%d.CurrentOperatingClassProfile.", root, idx);
        dm_ctrl->curops_tget_params(dm, path, ri, property);

        snprintf(path, sizeof(path) - 1, "%s%d.Capabilities.CapableOperatingClassProfile.", root, idx);
        dm_ctrl->capops_tget_params(dm, path, ri, property);

        snprintf(path, sizeof(path) - 1, "%s%d.Capabilities.WiFi6APRole.", root, idx);
        dm_ctrl->wf6ap_tget_params(dm, path, ri, property, idx);

        snprintf(path, sizeof(path) - 1, "%s%d.Capabilities.WiFi7APRole.", root, idx);
        dm_ctrl->wf7ap_tget_params(dm, path, ri, property, idx);

        snprintf(path, sizeof(path) - 1, "%s%d.BSS.", root, idx);
        dm_ctrl->bss_tget_params(dm, path, ri, property);
    }

    return rc;
}

void set_bh(bool b) { g_has_bh = b; memset(&g_sta, 0, sizeof(g_sta)); unsigned char m[6] = {2, 0, 0, 0, 0, 0xaa}; memcpy(g_sta.info.id, m, 6); }

int invoke(const char *root)
{
    bus_data_prop_t *prop = NULL;
    return (int)g_ctrl.m_data_model.radio_tget_params(g_dm, root, &prop);
}

} /* namespace rtp */
