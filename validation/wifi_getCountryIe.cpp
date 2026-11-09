/*
 * HANDLER: wifi_getCountryIe
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/banana-pi/platform.c:947 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub: it returns
 * 0 and never writes *enabled.  This file holds the ORIGINAL code: no fix is applied.  Renamed hwr_wifi_getCountryIe because the other
 * platforms define the same name.
 */
#include "hwr_gci.h"

#define wifi_getCountryIe hwr_wifi_getCountryIe

/* --- platform.c:947 --- */
extern "C" {
INT wifi_getCountryIe(INT apIndex, BOOL *enabled)
{
    return 0;
}
}
