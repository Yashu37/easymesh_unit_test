/*
 * HANDLER: wifi_hal_setRadioTransmitPower (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:2374-2398 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It looks the radio up, picks the interface with
 * get_primary_interface() when g_wifi_hal.platform_flags has PLATFORM_FLAGS_UPDATE_WIPHY_ON_PRIMARY set and with get_private_vap_interface() otherwise, returns -1 when there is none and else returns
 * RETURN_ERR / RETURN_OK for the non-zero / zero result of wifi_drv_set_txpower(interface, txpower).
 *
 * Scaffolding only: get_radio_by_rdk_index / get_primary_interface / get_private_vap_interface / wifi_drv_set_txpower are recording stubs over the runner's world; g_wifi_hal is the stand-in
 * hwr_wtp_world.hal; the *_print macros go to the log sink hwr_print.  Renamed hwr_sg_wifi_hal_setRadioTransmitPower.
 */
#include "hwr_wtp.h"
#include <stdio.h>
#include <string.h>

#define wifi_hal_error_print(format, ...)        hwr_print(1, format, ##__VA_ARGS__)
#define g_wifi_hal hwr_wtp_world.hal
#define get_radio_by_rdk_index hwr_wtp_get_radio_by_rdk_index
#define get_primary_interface hwr_wtp_get_primary_interface
#define get_private_vap_interface hwr_wtp_get_private_vap_interface
#define wifi_drv_set_txpower hwr_wtp_wifi_drv_set_txpower
#define wifi_hal_setRadioTransmitPower hwr_sg_wifi_hal_setRadioTransmitPower

hwr_wtp_world_t hwr_wtp_world;

extern "C" {
wifi_radio_info_t *get_radio_by_rdk_index(wifi_radio_index_t index)
{
    if (hwr_wtp_world.no_radio || index >= HWR_WTP_MAXR) return NULL;
    return &hwr_wtp_world.radios[index];
}
wifi_interface_info_t *get_primary_interface(wifi_radio_info_t *radio)
{
    hwr_wtp_world.primary_calls++; hwr_wtp_world.primary_arg = radio;
    return hwr_wtp_world.has_primary ? &hwr_wtp_world.primary[radio->index] : NULL;
}
wifi_interface_info_t *get_private_vap_interface(wifi_radio_info_t *radio)
{
    hwr_wtp_world.private_calls++; hwr_wtp_world.private_arg = radio;
    return hwr_wtp_world.has_private ? &hwr_wtp_world.priv[radio->index] : NULL;
}
int wifi_drv_set_txpower(void *priv, uint txpower)
{
    hwr_wtp_world.drv_calls++; hwr_wtp_world.drv_iface = priv; hwr_wtp_world.drv_txpower = txpower;
    return hwr_wtp_world.drv_ret;
}

/* --- wifi_hal.c:2374-2398 --- */
INT wifi_hal_setRadioTransmitPower(wifi_radio_index_t radioIndex, uint txpower)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;

    radio = get_radio_by_rdk_index(radioIndex);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d: radio for radio index:%d not found\n", __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }

    if (g_wifi_hal.platform_flags & PLATFORM_FLAGS_UPDATE_WIPHY_ON_PRIMARY) {
        interface = get_primary_interface(radio);
    }
    else {
        interface = get_private_vap_interface(radio);
    }

    if (!interface) {
        wifi_hal_error_print("%s:%d: Error updating dev:%d no interfaces exist\n", __func__, __LINE__, radio->index);
        return -1;
    }

    return wifi_drv_set_txpower(interface, txpower) ? RETURN_ERR : RETURN_OK;
}
}
