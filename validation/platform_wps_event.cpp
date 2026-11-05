/*
 * HANDLER: platform_wps_event
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/banana-pi/platform.c:263 (~/Desktop/G/rdk-wifi-hal).  It only logs through
 * wifi_hal_dbg_print and returns 0; the event (passed BY VALUE) is not used.  There is no fix switch because there is no finding.
 * wifi_wps_event_t is the type of src/wifi_hal_rdk_framework.h:117-121 (hwr_pwe.h).  The print is the real macro over the log sink.
 * Renamed hwr_platform_wps_event because the other platforms define the same name.
 */
#include "hwr_pwe.h"
#include <stdio.h>

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define platform_wps_event                 hwr_platform_wps_event

/* --- platform.c:263 --- */
extern "C" {
int platform_wps_event(wifi_wps_event_t data)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);  
    return 0;
}
}
