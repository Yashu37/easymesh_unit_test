/*
 * HANDLER: wifi_setCountryIe
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/banana-pi/platform.c:937 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub that returns
 * 0 (success) for every input and keeps no state, so nothing is observable and there is no finding and no fix switch.
 * Renamed hwr_wifi_setCountryIe because the other platforms define the same name.
 */
#include "hwr_sci.h"

#define wifi_setCountryIe hwr_wifi_setCountryIe

/* --- platform.c:937 --- */
extern "C" {
INT wifi_setCountryIe(INT apIndex, BOOL enabled)
{
    return 0;
}
}
