/*
 * HANDLER: wifi_setApIsolationEnable
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/banana-pi/platform.c:915 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub that returns
 * RETURN_ERR for every input: the feature is explicitly reported as unsupported on this platform, so there is no finding and no fix switch.
 * Renamed hwr_wifi_setApIsolationEnable because the other platforms define the same name.
 */
#include "hwr_sai.h"

#define wifi_setApIsolationEnable hwr_wifi_setApIsolationEnable

/* --- platform.c:915 --- */
extern "C" {
INT wifi_setApIsolationEnable(INT apIndex, BOOL enable)
{
    return RETURN_ERR;
}
}
