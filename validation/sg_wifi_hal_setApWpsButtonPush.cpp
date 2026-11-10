/*
 * HANDLER: wifi_hal_setApWpsButtonPush (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:380-387 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code: no fix is applied.
 * It logs the index, hands it to wifi_hal_nl80211_wps_pbc() (src/wifi_hal_nl80211.c:7720, an unsigned parameter: a negative index becomes a large value; that function
 * has its own entry later in the list) and returns 0 whatever happens.
 *
 * Scaffolding only: wifi_hal_nl80211_wps_pbc is a stub that records the call; the print macro maps to the log sink hwr_print.  Renamed hwr_sg_wifi_hal_setApWpsButtonPush.
 */
#include "hwr_wpb.h"

#define wifi_hal_info_print(format, ...)   hwr_print(0, format, ##__VA_ARGS__)
#define INT int
#define wifi_hal_nl80211_wps_pbc hwr_wpb_nl80211_wps_pbc
#define wifi_hal_setApWpsButtonPush hwr_sg_wifi_hal_setApWpsButtonPush

hwr_wpb_world_t hwr_wpb_world;

extern "C" {
void wifi_hal_nl80211_wps_pbc(unsigned int ap_index) { hwr_wpb_world.calls++; hwr_wpb_world.last_index = ap_index; }

/* --- wifi_hal.c:380-387 --- */
INT wifi_hal_setApWpsButtonPush(INT ap_index)
{
    wifi_hal_info_print("%s:%d: WPS Push Button for radio index %d\n", __func__, __LINE__, ap_index);

    wifi_hal_nl80211_wps_pbc(ap_index);

    return 0;
}
}
