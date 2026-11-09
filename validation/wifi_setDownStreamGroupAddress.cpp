/*
 * HANDLER: wifi_setDownStreamGroupAddress
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/banana-pi/platform.c:968 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub that returns
 * 0 (success) for every input and keeps no state, so nothing is observable and there is no finding and no fix switch.
 * Renamed hwr_wifi_setDownStreamGroupAddress because the other platforms define the same name.
 */
#include "hwr_sdg.h"

#define wifi_setDownStreamGroupAddress hwr_wifi_setDownStreamGroupAddress

/* --- platform.c:968 --- */
extern "C" {
INT wifi_setDownStreamGroupAddress(INT apIndex, BOOL disabled)
{
    return 0;
}
}
