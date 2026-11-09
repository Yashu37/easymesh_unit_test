/*
 * HANDLER: wifi_getLayer2TrafficInspectionFiltering
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/intel/platform.c:1838-1841 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub that returns
 * RETURN_ERR for every input and never writes *enabled: the feature is explicitly reported as unsupported on this platform, so there is no finding.  There is no fix switch.  Renamed hwr_int_wifi_getLayer2TrafficInspectionFiltering because the other
 * platforms define the same name.
 */
#include "hwr_il2.h"

#define wifi_getLayer2TrafficInspectionFiltering hwr_int_wifi_getLayer2TrafficInspectionFiltering

/* --- platform.c:1838-1841 --- */
extern "C" {
INT wifi_getLayer2TrafficInspectionFiltering(INT apIndex, BOOL *enabled)
{
    return RETURN_ERR;
}
}
