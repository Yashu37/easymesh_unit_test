/*
 * HANDLER: wifi_getProxyArp
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/banana-pi/platform.c:957 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub: it returns
 * 0 and never writes *enabled.  This file holds the ORIGINAL code: no fix is applied.  Renamed hwr_wifi_getProxyArp because the other
 * platforms define the same name.
 */
#include "hwr_gpa.h"

#define wifi_getProxyArp hwr_wifi_getProxyArp

/* --- platform.c:957 --- */
extern "C" {
INT wifi_getProxyArp(INT apIndex, BOOL *enabled)
{
    return 0;
}
}
