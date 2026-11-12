/*
 * HANDLER: wifi_hal_is_wps_enabled (src/wifi_hal_hostapd.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal_hostapd.c:1012-1017 (~/Desktop/G/rdk-wifi-hal; static, compiled under CONFIG_WPS).  This file holds the ORIGINAL code (no fixes).  WPS is enabled
 * for a VAP when its WPS flag is set, the BSS does not hide its SSID (ignore_broadcast_ssid == 0) and the radio is not on the 6 GHz band.
 *
 * Scaffolding only: stand-in radio / bss config types (hwr_wie.h); renamed hwr_sg_wifi_hal_is_wps_enabled.
 */
#include "hwr_wie.h"

#define wifi_hal_is_wps_enabled hwr_sg_wifi_hal_is_wps_enabled

extern "C" {
/* --- wifi_hal_hostapd.c:1012-1017 --- */
bool wifi_hal_is_wps_enabled(wifi_radio_info_t *radio, wifi_vap_info_t *vap,
    struct hostapd_bss_config *conf)
{
    return vap->u.bss_info.wps.enable && !conf->ignore_broadcast_ssid &&
        radio->oper_param.band != WIFI_FREQUENCY_6_BAND;
}
}
