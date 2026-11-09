/*
 * HANDLER: wifi_setP2PCrossConnect
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/banana-pi/platform.c:983 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub that returns
 * 0 (success) for every input and keeps no state, so nothing is observable and there is no finding and no fix switch.
 * Renamed hwr_wifi_setP2PCrossConnect because the other platforms define the same name.
 */
#include "hwr_spc.h"

#define wifi_setP2PCrossConnect hwr_wifi_setP2PCrossConnect

/* --- platform.c:983 --- */
extern "C" {
INT wifi_setP2PCrossConnect(INT apIndex, BOOL disabled)
{
    return 0;
}
}
