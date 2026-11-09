/*
 * HANDLER: wifi_setProxyArp
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/banana-pi/platform.c:932 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub that returns
 * 0 (success) for every input and keeps no state, so nothing is observable and there is no finding and no fix switch.
 * Renamed hwr_wifi_setProxyArp because the other platforms define the same name.
 */
#include "hwr_spa.h"

#define wifi_setProxyArp hwr_wifi_setProxyArp

/* --- platform.c:932 --- */
extern "C" {
INT wifi_setProxyArp(INT apIndex, BOOL enable)
{
    return 0;
}
}
