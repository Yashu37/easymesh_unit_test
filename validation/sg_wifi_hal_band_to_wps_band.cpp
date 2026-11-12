/*
 * HANDLER: wifi_hal_band_to_wps_band (src/wifi_hal_hostapd.c)
 *
 * Function copied (verbatim apart from the marked fix) from rdk-wifi-hal: src/wifi_hal_hostapd.c:989-1010 (~/Desktop/G/rdk-wifi-hal; static, compiled under CONFIG_WPS).  This file holds the code WITH fix 1 (start fix 1 / end fix 1 markers; the unfixed copy is the reproducer).  It converts a HAL
 * frequency band to the WPS RF band value: 2.4 GHz -> WPS_RF_24GHZ, 5 / 5L / 5H -> WPS_RF_50GHZ, 6 GHz -> 0 (WPS not supported there), anything else -> RETURN -1 (nothing written).
 *
 * Scaffolding only: WPS_RF_* constants as in hostap wps_defs.h; wifi_hal_error_print is a no-op; renamed hwr_sg_wifi_hal_band_to_wps_band.
 */
#include "hwr_wbw.h"

#define WPS_RF_24GHZ 0x01
#define WPS_RF_50GHZ 0x02
#define WPS_RF_60GHZ 0x04
static void hwr_wbw_err(const char *format, ...) { }
#define wifi_hal_error_print hwr_wbw_err
#define wifi_hal_band_to_wps_band hwr_sg_wifi_hal_band_to_wps_band

extern "C" {
/* --- wifi_hal_hostapd.c:989-1010 --- */
int wifi_hal_band_to_wps_band(wifi_freq_bands_t hal_band, u8 *wps_band)
{
    /* ---------- start fix 1: wps_band was written through without a NULL check. */
    if (wps_band == NULL) {
        return -1;
    }
    /* ---------- end fix 1 */

    switch (hal_band) {
    case WIFI_FREQUENCY_2_4_BAND:
        *wps_band = WPS_RF_24GHZ;
        break;
    case WIFI_FREQUENCY_5_BAND:
    case WIFI_FREQUENCY_5L_BAND:
    case WIFI_FREQUENCY_5H_BAND:
        *wps_band = WPS_RF_50GHZ;
        break;
    case WIFI_FREQUENCY_6_BAND:
        /* WPS is not supported in 6G */
        *wps_band = 0;
        break;
    default:
        wifi_hal_error_print("%s:%d Unsupported frequency band\n", __func__, __LINE__);
        return -1;
    }

    return 0;
}
}
