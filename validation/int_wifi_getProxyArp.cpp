/*
 * HANDLER: wifi_getProxyArp
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/intel/platform.c:1862-1865 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub that returns
 * RETURN_ERR for every input and never writes *enabled: the feature is explicitly reported as unsupported on this platform, so there is no finding.  There is no fix switch.  Renamed hwr_int_wifi_getProxyArp because the other
 * platforms define the same name.
 */
#include "hwr_igp.h"

#define wifi_getProxyArp hwr_int_wifi_getProxyArp

/* --- platform.c:1862-1865 --- */
extern "C" {
INT wifi_getProxyArp(INT apIndex, BOOL *enabled)
{
    return RETURN_ERR;
}
}
