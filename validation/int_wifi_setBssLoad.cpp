/*
 * HANDLER: wifi_setBssLoad (platform/intel)
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/intel/platform.c:1886-1889 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub that returns
 * RETURN_ERR for every input: the feature is explicitly reported as unsupported on this platform, so there is no finding and no fix switch.
 * (The banana-pi stub returns 0 here; the intel stub reports "unsupported" with RETURN_ERR.)  Renamed hwr_int_wifi_setBssLoad because the other platforms define
 * the same name.
 */
#include "hwr_isb.h"

#define wifi_setBssLoad hwr_int_wifi_setBssLoad

/* --- platform.c:1886-1889 --- */
extern "C" {
INT wifi_setBssLoad(INT apIndex, BOOL enabled)
{
    return RETURN_ERR;
}
}
