/*
 * HANDLER: wifi_getBssLoad
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/banana-pi/platform.c:963 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub that returns
 * RETURN_ERR for every input and never writes *enabled: the feature is explicitly reported as unsupported on this platform, so there is no finding.  There is no fix switch.  Renamed hwr_wifi_getBssLoad because the other
 * platforms define the same name.
 */
#include "hwr_gbl.h"

#define wifi_getBssLoad hwr_wifi_getBssLoad

/* --- platform.c:963 --- */
extern "C" {
INT wifi_getBssLoad(INT apIndex, BOOL *enabled)
{
    return RETURN_ERR;
}
}
