/*
 * HANDLER: wifi_getLayer2TrafficInspectionFiltering
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/banana-pi/platform.c:942 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub: it returns
 * 0 and never writes *enabled.  This file holds the ORIGINAL code: no fix is applied.  Renamed hwr_wifi_getLayer2TrafficInspectionFiltering because the other
 * platforms define the same name.
 */
#include "hwr_gl2.h"

#define wifi_getLayer2TrafficInspectionFiltering hwr_wifi_getLayer2TrafficInspectionFiltering

/* --- platform.c:942 --- */
extern "C" {
INT wifi_getLayer2TrafficInspectionFiltering(INT apIndex, BOOL *enabled)
{
    return 0;
}
}
