/*
 * HANDLER: get_sta_vht_caps_str
 *
 * Function copied (fix 1 applied, start fix n / end fix n markers) from unified-wifi-mesh src/ctrl/dm_easy_mesh_ctrl.cpp
 * (develop @ 1ba9529), dm_easy_mesh_ctrl_t::get_sta_vht_caps_str, with dm_easy_mesh_t::unhex()
 * (src/dm/dm_easy_mesh.cpp, verbatim). Local arrays: ie[16], data[6]; the input is the caller's
 * em_sta_info_t.vht_cap (em_long_string_t, 128 bytes) and strlen() is run on it; the output is the
 * caller's caps_str[32].
 * Scaffolding: em_crypto_t::base64_encode (same algorithm as src/em/crypto), g_ctrl.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <string>
#include "get_sta_vht_caps_str.h"

namespace gsv {

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
char* dm_easy_mesh_ctrl_t::get_sta_vht_caps_str(char *vht_cap_hex, char *buf, size_t buf_len)
{
    unsigned char ie[16] = {0};
    unsigned int hex_len;
    unsigned int cap_info;
    unsigned short rx_map, tx_map;
    uint8_t data[6] = {0};
    uint8_t rx_nss = 1, tx_nss = 1, cw_set;
    unsigned int i;

    buf[0] = '\0';
    if ((vht_cap_hex == NULL) || (vht_cap_hex[0] == '\0')) {
        return buf;
    }
/* start fix 1 */
    hex_len = static_cast<unsigned int>(strnlen(vht_cap_hex, 2 * sizeof(ie) + 1));
/* end fix 1 */
    if ((hex_len < 24) || (hex_len & 1) || (hex_len > 2 * sizeof(ie)) ||
        (dm_easy_mesh_t::unhex(hex_len, vht_cap_hex, sizeof(ie), ie) == NULL)) {
        return buf;
    }

    cap_info = static_cast<unsigned int>(ie[0]) | (static_cast<unsigned int>(ie[1]) << 8) |
               (static_cast<unsigned int>(ie[2]) << 16) | (static_cast<unsigned int>(ie[3]) << 24);
    cw_set = (cap_info >> 2) & 0x03;
    rx_map = static_cast<unsigned short>(ie[4] | (ie[5] << 8));
    tx_map = static_cast<unsigned short>(ie[8] | (ie[9] << 8));

    /* MCS/NSS maps: 2 bits per stream, 0x3 = not supported */
    for (i = 0; i < 8; i++) {
        if (((rx_map >> (2 * i)) & 0x03) != 0x03) {
            rx_nss = static_cast<uint8_t>(i + 1);
        }
        if (((tx_map >> (2 * i)) & 0x03) != 0x03) {
            tx_nss = static_cast<uint8_t>(i + 1);
        }
    }

    data[0] = static_cast<uint8_t>(tx_map >> 8);
    data[1] = static_cast<uint8_t>(tx_map & 0xff);
    data[2] = static_cast<uint8_t>(rx_map >> 8);
    data[3] = static_cast<uint8_t>(rx_map & 0xff);
    data[4]  = static_cast<uint8_t>(((tx_nss - 1) & 0x07) << 5);
    data[4] |= static_cast<uint8_t>(((rx_nss - 1) & 0x07) << 2);
    data[4] |= static_cast<uint8_t>(((cap_info >> 5) & 1) << 1);  /* SGI 80 MHz */
    data[4] |= static_cast<uint8_t>((cap_info >> 6) & 1);         /* SGI 160 MHz */
    data[5]  = static_cast<uint8_t>((cw_set == 2 ? 1 : 0) << 7);  /* 80+80 MHz */
    data[5] |= static_cast<uint8_t>((cw_set >= 1 ? 1 : 0) << 6);  /* 160 MHz */
    data[5] |= static_cast<uint8_t>(((cap_info >> 11) & 1) << 5); /* SU beamformer */
    data[5] |= static_cast<uint8_t>(((cap_info >> 19) & 1) << 4); /* MU beamformer */

    std::string encoded = em_crypto_t::base64_encode(data, sizeof(data));
    snprintf(buf, buf_len, "%s", encoded.c_str());
    return buf;
}

const char *invoke(char *hex, char *buf, size_t buf_len)
{
    return g_ctrl_obj.get_sta_vht_caps_str(hex, buf, buf_len);
}

} /* namespace gsv */
