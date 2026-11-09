/*
 * HANDLER: wifi_setLayer2TrafficInspectionFiltering
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/banana-pi/platform.c:989 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub that returns
 * RETURN_ERR for every input: the feature is explicitly reported as unsupported on this platform, so there is no finding and no fix switch.
 * Renamed hwr_wifi_setLayer2TrafficInspectionFiltering because the other platforms define the same name.
 */
#include "hwr_sl2.h"

#define wifi_setLayer2TrafficInspectionFiltering hwr_wifi_setLayer2TrafficInspectionFiltering

/* --- platform.c:989 --- */
extern "C" {
INT wifi_setLayer2TrafficInspectionFiltering(INT apIndex, BOOL enabled)
{
    return RETURN_ERR;
}
}
