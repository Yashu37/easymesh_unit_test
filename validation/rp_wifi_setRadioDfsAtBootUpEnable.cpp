/*
 * HANDLER: wifi_setRadioDfsAtBootUpEnable (platform/raspberry-pi)
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/raspberry-pi/platform_pi.c:633-636 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub that returns
 * 0 (success) for every input: the DFS-at-boot request is accepted and ignored (design note, same class as the banana-pi setter stubs, not counted).  No fix switch.
 * Renamed hwr_rp_wifi_setRadioDfsAtBootUpEnable because the other platforms define the same name.
 */
#include "hwr_rdb.h"

#define wifi_setRadioDfsAtBootUpEnable hwr_rp_wifi_setRadioDfsAtBootUpEnable

/* --- platform_pi.c:633-636 --- */
extern "C" {
INT wifi_setRadioDfsAtBootUpEnable(INT radioIndex, BOOL enable) // Tr181
{
    return 0;
}
}
