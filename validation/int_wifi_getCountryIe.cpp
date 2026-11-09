/*
 * HANDLER: wifi_getCountryIe
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/intel/platform.c:1844-1847 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub that returns
 * RETURN_ERR for every input and never writes *enabled: the feature is explicitly reported as unsupported on this platform, so there is no finding.  There is no fix switch.  Renamed hwr_int_wifi_getCountryIe because the other
 * platforms define the same name.
 */
#include "hwr_ice.h"

#define wifi_getCountryIe hwr_int_wifi_getCountryIe

/* --- platform.c:1844-1847 --- */
extern "C" {
INT wifi_getCountryIe(INT apIndex, BOOL *enabled)
{
    return RETURN_ERR;
}
}
