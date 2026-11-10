/*
 * HANDLER: wifi_hal_setApWpsCancel (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:389-396 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code: no fix is applied.
 * It logs the index, hands it to wifi_hal_nl80211_wps_cancel() (src/wifi_hal_nl80211.c:7738, an unsigned parameter: a negative index becomes a large value; that function
 * has its own entry later in the list) and returns 0 whatever happens.
 *
 * Scaffolding only: wifi_hal_nl80211_wps_cancel is a stub that records the call; the print macro maps to the log sink hwr_print.  Renamed hwr_sg_wifi_hal_setApWpsCancel.
 */
#include "hwr_wpc.h"

#define wifi_hal_info_print(format, ...)   hwr_print(0, format, ##__VA_ARGS__)
#define INT int
#define wifi_hal_nl80211_wps_cancel hwr_wpc_nl80211_wps_cancel
#define wifi_hal_setApWpsCancel hwr_sg_wifi_hal_setApWpsCancel

hwr_wpc_world_t hwr_wpc_world;

extern "C" {
void wifi_hal_nl80211_wps_cancel(unsigned int ap_index) { hwr_wpc_world.calls++; hwr_wpc_world.last_index = ap_index; }

/* --- wifi_hal.c:389-396 --- */
INT wifi_hal_setApWpsCancel(INT ap_index)
{
    wifi_hal_info_print("%s:%d: WPS Cancel session for radio index %d\n", __func__, __LINE__, ap_index);

    wifi_hal_nl80211_wps_cancel(ap_index);

    return 0;
}
}
