/*
 * HANDLER: wifi_setBssLoad
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/banana-pi/platform.c:973 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub that returns
 * 0 (success) for every input and keeps no state, so nothing is observable and there is no finding and no fix switch.
 * Renamed hwr_wifi_setBssLoad because the other platforms define the same name.
 */
#include "hwr_sbl.h"

#define wifi_setBssLoad hwr_wifi_setBssLoad

/* --- platform.c:973 --- */
extern "C" {
INT wifi_setBssLoad(INT apIndex, BOOL enabled)
{
    return 0;
}
}
