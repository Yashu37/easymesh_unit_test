/*
 * HANDLER: wifi_getRadioChannelStats
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/banana-pi/platform.c:675 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub: it returns
 * RETURN_OK and never fills input_output_channelStats_array.  This file holds the ORIGINAL code: no fix is applied.  Renamed
 * hwr_wifi_getRadioChannelStats because the other platforms (and the wifi_hal_getRadioChannelStats harness) define the same name.
 */
#include "hwr_gks.h"

#define wifi_getRadioChannelStats hwr_wifi_getRadioChannelStats

/* --- platform.c:675 --- */
extern "C" {
INT wifi_getRadioChannelStats(INT radioIndex, wifi_channelStats_t *input_output_channelStats_array,
    INT array_size)
{
    return RETURN_OK;
}
}
