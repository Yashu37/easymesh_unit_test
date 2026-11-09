/*
 * HANDLER: wifi_pushApHotspotElement (platform/intel)
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/intel/platform.c:1880-1883 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub that returns
 * RETURN_ERR for every input: the feature is explicitly reported as unsupported on this platform, so there is no finding and no fix switch.
 * (The banana-pi stub returns 0 here; the intel stub reports "unsupported" with RETURN_ERR.)  Renamed hwr_int_wifi_pushApHotspotElement because the other platforms define
 * the same name.
 */
#include "hwr_iph.h"

#define wifi_pushApHotspotElement hwr_int_wifi_pushApHotspotElement

/* --- platform.c:1880-1883 --- */
extern "C" {
INT wifi_pushApHotspotElement(INT apIndex, BOOL enabled)
{
    return RETURN_ERR;
}
}
