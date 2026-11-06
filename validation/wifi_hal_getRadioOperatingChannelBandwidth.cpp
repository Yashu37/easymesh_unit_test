/*
 * HANDLER: wifi_hal_getRadioOperatingChannelBandwidth
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc_wifi_wrappers.c:514-550 (~/Desktop/G/rdk-wifi-hal), with
 * get_radio_by_rdk_index (src/wifi_hal_nl80211_utils.c:2271-2283) copied verbatim next to it (declared static here only
 * so the harnesses link together).  This file holds ONLY THE FIXED code: it carries FIX 1..2 below.
 *
 * Scaffolding only: g_wifi_hal / the radio hold just num_radios, radio_info[], rdk_radio_index and the REAL
 * wifi_radio_operationParam_t (wifi_hal.h); the function under test is renamed
 * hwr_wifi_hal_getRadioOperatingChannelBandwidth (ipc_server_output already stubs the real name).
 */
#include "hwr_gcb.h"
#include <stdio.h>


#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define wifi_radio_info_t     hwr_gcb_radio_t
#define g_wifi_hal            hwr_gcb_world
#define wifi_hal_getRadioOperatingChannelBandwidth hwr_wifi_hal_getRadioOperatingChannelBandwidth

hwr_gcb_world_t hwr_gcb_world;

/* --- copied from wifi_hal_nl80211_utils.c:2271 --- */
static wifi_radio_info_t *get_radio_by_rdk_index(wifi_radio_index_t index)
{
    wifi_radio_info_t *radio;
    unsigned int i;

    for (i = 0; i < g_wifi_hal.num_radios; i++) {
        radio = &g_wifi_hal.radio_info[i];
        if (radio->rdk_radio_index == index) {
            return radio;
        }
    }
    return NULL;
}

/* --- copied from hal_ipc_wifi_wrappers.c:514 --- */
extern "C" {
INT wifi_hal_getRadioOperatingChannelBandwidth( INT radioIndex,
                                                CHAR *output_string)
{
    wifi_radio_info_t *radio = NULL;
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);

    /* FIX 1: output_string is written unchecked (snprintf with a NULL buffer and a non-zero size). */
    if (output_string == NULL) {
        return RETURN_ERR;
    }
    radio = get_radio_by_rdk_index(radioIndex);

    if(!radio){
      wifi_hal_error_print("%s:%d: radio pointer is NULL!.\n", __func__, __LINE__);
      return RETURN_ERR;
    }

    switch (radio->oper_param.channelWidth) {
        case WIFI_CHANNELBANDWIDTH_20MHZ:
            snprintf(output_string, 6, "20MHz");
            break;

        case WIFI_CHANNELBANDWIDTH_40MHZ:
            snprintf(output_string, 6, "40MHz");
            break;

        case WIFI_CHANNELBANDWIDTH_80MHZ:
            snprintf(output_string, 6, "80MHz");
            break;

        case WIFI_CHANNELBANDWIDTH_160MHZ:
            snprintf(output_string, 7, "160MHz");
            break;

        /* FIX 2: 80+80MHz and 320MHz fell through to the default and were reported as "20MHz"; the strings are
         * the ones of wifi_bandwidth_Map (wifi_hal_nl80211_utils.c:1820). */
        case WIFI_CHANNELBANDWIDTH_80_80MHZ:
            snprintf(output_string, 9, "80+80MHz");
            break;

        case WIFI_CHANNELBANDWIDTH_320MHZ:
            snprintf(output_string, 7, "320MHz");
            break;

        default:
            snprintf(output_string, 6, "20MHz");
            break;
    }

    return 0;
}
}
