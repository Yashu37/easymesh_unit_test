/*
 * HANDLER: wifi_hal_setApWpsPin (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:398-409 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code: no fix is applied.
 * A NULL wps_pin is rejected with RETURN_ERR; otherwise the pin is logged and the result of wifi_hal_nl80211_wps_pin() (src/wifi_hal_nl80211.c:7757, its own entry later in
 * the list) is returned.  The pin's content / length is not validated here (the callee's job).
 *
 * Scaffolding only: wifi_hal_nl80211_wps_pin is a stub that records the call and returns the runner's value; the print macros map to the log sink hwr_print.  Renamed
 * hwr_sg_wifi_hal_setApWpsPin.
 */
#include "hwr_wpp.h"

#define wifi_hal_info_print(format, ...)   hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)  hwr_print(0, format, ##__VA_ARGS__)
#define INT int
#define RETURN_ERR -1
#define wifi_hal_nl80211_wps_pin hwr_wpp_nl80211_wps_pin
#define wifi_hal_setApWpsPin hwr_sg_wifi_hal_setApWpsPin

hwr_wpp_world_t hwr_wpp_world;

extern "C" {
int wifi_hal_nl80211_wps_pin(unsigned int ap_index, char *wps_pin)
{
    hwr_wpp_world.calls++; hwr_wpp_world.last_index = ap_index; hwr_wpp_world.last_pin = wps_pin;
    return hwr_wpp_world.ret;
}

/* --- wifi_hal.c:398-409 --- */
INT wifi_hal_setApWpsPin(INT ap_index, char *wps_pin)
{
    if (wps_pin == NULL) {
        wifi_hal_error_print("%s:%d: WPS Pin is NULL for vap_index:%d\n", __func__, __LINE__, ap_index);
        return RETURN_ERR;
    }

    wifi_hal_info_print("%s:%d: WPS Pin configuration for vap_index:%d pin:%s\n",
                                __func__, __LINE__, ap_index, wps_pin);

    return (wifi_hal_nl80211_wps_pin(ap_index, wps_pin));
}
}
