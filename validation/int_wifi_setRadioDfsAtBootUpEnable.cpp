/*
 * HANDLER: wifi_setRadioDfsAtBootUpEnable (platform/intel)
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/intel/platform.c:1800-1803 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub that returns
 * RETURN_ERR for every input: the feature is explicitly reported as unsupported on this platform, so there is no finding and no fix switch.
 * Renamed hwr_int_wifi_setRadioDfsAtBootUpEnable because the other platforms define the same name.
 */
#include "hwr_idb.h"

#define wifi_setRadioDfsAtBootUpEnable hwr_int_wifi_setRadioDfsAtBootUpEnable

/* --- platform.c:1800-1803 --- */
extern "C" {
INT wifi_setRadioDfsAtBootUpEnable(INT radioIndex, BOOL enabled)
{
    return RETURN_ERR;
}
}
