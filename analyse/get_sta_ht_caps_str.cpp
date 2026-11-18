/*
 * HANDLER: get_sta_ht_caps_str
 *
 * Function copied verbatim (no fix applied yet) from unified-wifi-mesh src/ctrl/dm_easy_mesh_ctrl.cpp
 * (develop @ 1ba9529), dm_easy_mesh_ctrl_t::get_sta_ht_caps_str, with dm_easy_mesh_t::unhex()
 * (src/dm/dm_easy_mesh.cpp, verbatim). Local array: ie[32]; the input is the caller's
 * em_sta_info_t.ht_cap (em_long_string_t, 128 bytes) and strlen() is run on it; the output is the
 * caller's caps_str[32].
 * Scaffolding: em_crypto_t::base64_encode (same algorithm as src/em/crypto), g_ctrl_obj.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <string>
#include "get_sta_ht_caps_str.h"

namespace gsh {

static dm_easy_mesh_ctrl_t g_ctrl_obj;

/* --- copied verbatim from src/dm/dm_easy_mesh.cpp --- */
unsigned char *dm_easy_mesh_t::unhex(unsigned int in_len, char *in, unsigned int out_len, unsigned char *out)
{
    unsigned int i;
    unsigned char tmp1, tmp2;

    if (out_len < in_len/2) {
        return NULL;
    }

    for (i = 0; i < in_len/2; i++) {
        if (in[2*i] <= '9') {
            tmp1 = static_cast<unsigned char> (in[2*i]) - 0x30;
        } else {
            tmp1 = static_cast<unsigned char> (in[2*i]) - 0x61 + 0xa;
        }

        tmp1 = static_cast<unsigned char> (tmp1 << 4);

        if (in[2*i + 1] <= '9') {
            tmp2 = static_cast<unsigned char> (in[2*i + 1]) - 0x30;
        } else {
            tmp2 = static_cast<unsigned char> (in[2*i + 1]) - 0x61 + 0xa;
        }

        tmp2 &= 0xf;

        out[i] = tmp1 | tmp2;
    }

    return out;
}

/* --- copied verbatim from src/ctrl/dm_easy_mesh_ctrl.cpp --- */
char* dm_easy_mesh_ctrl_t::get_sta_ht_caps_str(char *ht_cap_hex, char *buf, size_t buf_len)
{
    unsigned char ie[32] = {0};
    unsigned int hex_len;
    unsigned short cap_info;
    uint8_t data = 0, rx_nss = 1, tx_nss;
    unsigned int i;

    buf[0] = '\0';
    if ((ht_cap_hex == NULL) || (ht_cap_hex[0] == '\0')) {
        return buf;
    }
    hex_len = static_cast<unsigned int>(strlen(ht_cap_hex));
    if ((hex_len < 32) || (hex_len & 1) || (hex_len > 2 * sizeof(ie)) ||
        (dm_easy_mesh_t::unhex(hex_len, ht_cap_hex, sizeof(ie), ie) == NULL)) {
        return buf;
    }

    cap_info = static_cast<unsigned short>(ie[0] | (ie[1] << 8));

    /* Supported MCS Set (offset 3): one rx bitmask byte per spatial stream */
    for (i = 0; i < 4; i++) {
        if (ie[3 + i] != 0) {
            rx_nss = static_cast<uint8_t>(i + 1);
        }
    }
    tx_nss = rx_nss;
    /* Tx MCS Set Defined + Tx Rx MCS Set Not Equal -> explicit max Tx NSS */
    if ((ie[15] & 0x01) && (ie[15] & 0x02)) {
        tx_nss = static_cast<uint8_t>(((ie[15] >> 2) & 0x03) + 1);
    }

    data  = static_cast<uint8_t>(((tx_nss - 1) & 0x03) << 6);
    data |= static_cast<uint8_t>(((rx_nss - 1) & 0x03) << 4);
    data |= static_cast<uint8_t>(((cap_info >> 5) & 1) << 3); /* SGI 20 MHz */
    data |= static_cast<uint8_t>(((cap_info >> 6) & 1) << 2); /* SGI 40 MHz */
    data |= static_cast<uint8_t>(((cap_info >> 1) & 1) << 1); /* HT 40 MHz */

    std::string encoded = em_crypto_t::base64_encode(&data, sizeof(data));
    snprintf(buf, buf_len, "%s", encoded.c_str());
    return buf;
}

const char *invoke(char *hex, char *buf, size_t buf_len)
{
    return g_ctrl_obj.get_sta_ht_caps_str(hex, buf, buf_len);
}

} /* namespace gsh */
