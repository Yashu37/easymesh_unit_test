/*
 * HANDLER: wifi_pushApHotspotElement
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/banana-pi/platform.c:994 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub that returns
 * 0 (success) for every input and keeps no state, so nothing is observable and there is no finding and no fix switch.
 * Renamed hwr_wifi_pushApHotspotElement because the other platforms define the same name.
 */
#include "hwr_pah.h"

#define wifi_pushApHotspotElement hwr_wifi_pushApHotspotElement

/* --- platform.c:994 --- */
extern "C" {
INT wifi_pushApHotspotElement(INT apIndex, BOOL enabled)
{
    return 0;
}
}
