/*
 * HANDLER: wifi_hal_getRadioOperatingFrequencyBand
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc_wifi_wrappers.c:237-261
 * (~/Desktop/G/rdk-wifi-hal), with get_radio_by_rdk_index (src/wifi_hal_nl80211_utils.c:2271-2283) copied
 * verbatim next to it (declared static here only so the harnesses link together).  With RDK_GFB_FIX 0 it is
 * the VERBATIM original (reproduces the findings); with RDK_GFB_FIX 1 it carries FIX 1..2 below.
 *
 * Scaffolding only: g_wifi_hal / the radio hold just num_radios, radio_info[], rdk_radio_index and the REAL
 * wifi_radio_operationParam_t (wifi_hal.h); the function under test is renamed
 * hwr_wifi_hal_getRadioOperatingFrequencyBand (ipc_server_output already stubs the real name).
 */
#include "hwr_gfb.h"
#include <stdio.h>

/* 1 = with FIX 1..2, 0 = original unfixed function (set to 0 to reproduce the findings) */
#define RDK_GFB_FIX  0

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define wifi_radio_info_t     hwr_gfb_radio_t
#define g_wifi_hal            hwr_gfb_world
#define wifi_hal_getRadioOperatingFrequencyBand hwr_wifi_hal_getRadioOperatingFrequencyBand

hwr_gfb_world_t hwr_gfb_world;

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

/* --- copied from hal_ipc_wifi_wrappers.c:237 --- */
extern "C" {
INT wifi_hal_getRadioOperatingFrequencyBand(INT radioIndex,
                                            CHAR *output_string)
{
    wifi_radio_info_t *radio = NULL;
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);

#if RDK_GFB_FIX
    /* FIX 1: output_string is written unchecked (snprintf with a NULL buffer and size 64). */
    if (output_string == NULL) {
        return RETURN_ERR;
    }
#endif
    radio = get_radio_by_rdk_index(radioIndex);

    if(!radio){
      wifi_hal_error_print("%s:%d: radio pointer is NULL!.\n", __func__, __LINE__);
      return RETURN_ERR;
    }

    if (radio->oper_param.band == WIFI_FREQUENCY_5_BAND ||
        radio->oper_param.band == WIFI_FREQUENCY_5L_BAND ||
        radio->oper_param.band == WIFI_FREQUENCY_5H_BAND) {
        snprintf(output_string, 64, "5GHz");
    } else if (radio->oper_param.band == WIFI_FREQUENCY_6_BAND) {
        snprintf(output_string, 64, "6GHz");
#if RDK_GFB_FIX
    /* FIX 2: WIFI_FREQUENCY_60_BAND fell through to the default and was reported as "2.4GHz". */
    } else if (radio->oper_param.band == WIFI_FREQUENCY_60_BAND) {
        snprintf(output_string, 64, "60GHz");
#endif
    } else {
        snprintf(output_string, 64, "2.4GHz");
    }

    return 0;
}
}
