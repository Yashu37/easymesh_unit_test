/*
 * HANDLER: platform_set_radio_pre_init
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/banana-pi/platform.c:125 (~/Desktop/G/rdk-wifi-hal).  It only logs through
 * wifi_hal_dbg_print and returns 0; index and operationParam are not used.  There is no fix switch because there is no finding.
 * The print is the real macro over the log sink.  Renamed hwr_platform_set_radio_pre_init because the other platforms define the same name.
 */
#include "hwr_psp.h"
#include <stdio.h>

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define platform_set_radio_pre_init                 hwr_platform_set_radio_pre_init

/* --- platform.c:125 --- */
extern "C" {
int platform_set_radio_pre_init(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    return 0;
}
}
