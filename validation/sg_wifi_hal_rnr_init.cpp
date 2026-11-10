/*
 * HANDLER: wifi_hal_rnr_init (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:2461-2485 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It clears radio->rnr and radio->rnr_enabled and, for a non-empty
 * ssid, stores its CRC-32, the flag have_ssid and the SSID (strncpy of at most sizeof(ssid_t) - 1 = 31 bytes); for a NULL / empty ssid only have_ssid = false.
 *
 * Scaffolding only: get_radio_by_rdk_index is a stub over the runner's world; rnr_crc32 is the real function (wifi_hal_nl80211_utils.c:3043-3053) copied as hwr_wri_crc32; the *_print macros go to the
 * log sink hwr_print.  Renamed hwr_sg_wifi_hal_rnr_init.
 */
#include "hwr_wri.h"
#include <stdio.h>
#include <string.h>

#define wifi_hal_error_print(format, ...)        hwr_print(1, format, ##__VA_ARGS__)
#define wifi_hal_dbg_print(format, ...)          hwr_print(0, format, ##__VA_ARGS__)
#define get_radio_by_rdk_index hwr_wri_get_radio_by_rdk_index
#define rnr_crc32 hwr_wri_crc32
#define wifi_hal_rnr_init hwr_sg_wifi_hal_rnr_init

hwr_wri_world_t hwr_wri_world;

extern "C" {
wifi_radio_info_t *get_radio_by_rdk_index(wifi_radio_index_t index)
{
    if (hwr_wri_world.no_radio || index >= HWR_WRI_MAXR) return NULL;
    return &hwr_wri_world.radios[index];
}
/* wifi_hal_nl80211_utils.c:3043-3053 */
uint32_t rnr_crc32(const uint8_t *p, size_t n)
{
    uint32_t c = 0xFFFFFFFFu;
    size_t i, b;

    for (i = 0; i < n; i++) {
        c ^= p[i];
        for (b = 0; b < 8; b++)
            c = (c >> 1) ^ ((c & 1u) ? 0xEDB88320u : 0u);
    }
    return c ^ 0xFFFFFFFFu;
}

/* --- wifi_hal.c:2461-2485 --- */
void wifi_hal_rnr_init(wifi_radio_index_t radio_index, const char *ssid)
{
    wifi_radio_info_t *radio = get_radio_by_rdk_index(radio_index);

    if (radio == NULL) {
        wifi_hal_error_print("%s:%d: [RNR] invalid radio_index=%d\n", __func__, __LINE__,
            radio_index);
        return;
    }

    memset(&radio->rnr, 0, sizeof(radio->rnr));
    radio->rnr_enabled = false;

    if (ssid != NULL && ssid[0] != '\0') {
        radio->rnr.ssid_crc = rnr_crc32((const uint8_t *)ssid, strlen(ssid));
        radio->rnr.have_ssid = true;
        strncpy(radio->rnr.ssid, ssid, sizeof(radio->rnr.ssid) - 1);
        wifi_hal_dbg_print("%s:%d: [RNR] init radio=%d ssid=\"%s\" "
                           "crc=0x%08X\n",
            __func__, __LINE__, radio_index, radio->rnr.ssid, radio->rnr.ssid_crc);
    } else {
        radio->rnr.have_ssid = false;
        wifi_hal_dbg_print("%s:%d: [RNR] init radio=%d no ssid\n", __func__, __LINE__, radio_index);
    }
}
}
