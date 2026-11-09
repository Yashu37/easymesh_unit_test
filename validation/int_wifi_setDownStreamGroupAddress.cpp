/*
 * HANDLER: wifi_setDownStreamGroupAddress (platform/intel)
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/intel/platform.c:1910-1913 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub that returns
 * RETURN_ERR for every input: the feature is explicitly reported as unsupported on this platform, so there is no finding and no fix switch.
 * (The banana-pi stub returns 0 here; the intel stub reports "unsupported" with RETURN_ERR.)  Renamed hwr_int_wifi_setDownStreamGroupAddress because the other platforms define
 * the same name.
 */
#include "hwr_isd.h"

#define wifi_setDownStreamGroupAddress hwr_int_wifi_setDownStreamGroupAddress

/* --- platform.c:1910-1913 --- */
extern "C" {
INT wifi_setDownStreamGroupAddress(INT apIndex, BOOL disabled)
{
    return RETURN_ERR;
}
}
