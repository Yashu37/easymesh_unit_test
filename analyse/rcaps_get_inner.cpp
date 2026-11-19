/*
 * HANDLER: rcaps_get_inner
 *
 * Function copied verbatim (no fix applied yet) from unified-wifi-mesh src/ctrl/dm_easy_mesh_ctrl.cpp
 * (develop @ 1ba9529), dm_easy_mesh_ctrl_t::rcaps_get_inner, with get_table_instance(), get_ht_caps_str(),
 * get_vht_caps_str() and get_supported_standards_str() (same file, all verbatim).
 * Local arrays: caps_str[MAX_CAPS_STR_LEN = 32], instance[MAX_INSTANCE_LEN = 32], supported_standards[MAX_STDLEN = 64];
 * array access dm->m_radio[radio_instance - 1] (EM_MAX_BANDS = 3); loop over dm->get_num_op_class() /
 * get_op_class(i) (m_op_class[64], get_num_op_class() does not clamp).
 * Scaffolding: one device 1 (or MAC alias 02:00:00:00:00:01) with radios 1..3 (RUID 02:00:00:00:00:r), radio caps
 * for radios 1 and 2 only; raw_data_set records the value it is given.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <string>
#include <type_traits>
#include "rcaps_get_inner.h"

namespace rcg {

char g_val[RCG_VAL_SZ];
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

bus_error_t dm_easy_mesh_ctrl_t::rcaps_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    (void) user_data;
    const char *name = event_name;
    const char *param;
    char caps_str[MAX_CAPS_STR_LEN] = { 0 };
    char instance[MAX_INSTANCE_LEN] = { 0 };
    char supported_standards[MAX_STDLEN] = { 0 };
    bool is_num;
    int radio_instance = 0;
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

    dm_radio_cap_t *radio_cap = dm->get_radio_cap(ri->id.ruid);

    if (strcmp(param, "CapableOperatingClassProfileNumberOfEntries") == 0) {
        unsigned int capop_count = 0;
        for (unsigned int i = 0; i < dm->get_num_op_class(); i++) {
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
        return dm_ctrl->raw_data_set(p_data, capop_count);
    }

    if (radio_cap == NULL) {
        em_printfout("radio_cap is NULL\n");
        return bus_error_invalid_input;
    }
    em_radio_cap_info_t *rci = radio_cap->get_radio_cap_info();

    if (strcmp(param, "HTCapabilities") == 0) {
        dm_ctrl->get_ht_caps_str(&rci->ht_cap, caps_str, sizeof(caps_str));
        rc = dm_ctrl->raw_data_set(p_data, caps_str);
    } else if (strcmp(param, "VHTCapabilities") == 0) {
        dm_ctrl->get_vht_caps_str(&rci->vht_cap, caps_str, sizeof(caps_str));
        rc = dm_ctrl->raw_data_set(p_data, caps_str);
    } else if (strcmp(param, "X_AIRTIES_OperatingStandards") == 0) {
        dm_ctrl->get_supported_standards_str(rci->mode, supported_standards, sizeof(supported_standards));
        rc = dm_ctrl->raw_data_set(p_data, supported_standards);
    } else {
        em_printfout("Invalid param: %s", param);
        rc = bus_error_invalid_input;
    }

    return rc;
}

int invoke(const char *event, bool no_pdata)
{
    raw_data_t raw;
    memset(&raw, 0, sizeof(raw));
    bus_user_data_t ud;
    return (int)g_ctrl.m_data_model.rcaps_get_inner(const_cast<char *>(event), no_pdata ? NULL : &raw, &ud);
}

} /* namespace rcg */
