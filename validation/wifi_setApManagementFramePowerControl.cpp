/*
 * HANDLER: wifi_setApManagementFramePowerControl
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/banana-pi/platform.c:1009 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub that returns
 * 0 (success) for every input and keeps no state, so nothing is observable and there is no finding and no fix switch.
 * Renamed hwr_wifi_setApManagementFramePowerControl because the other platforms define the same name.
 */
#include "hwr_smp.h"

#define wifi_setApManagementFramePowerControl hwr_wifi_setApManagementFramePowerControl

/* --- platform.c:1009 --- */
extern "C" {
INT wifi_setApManagementFramePowerControl(INT apIndex, INT dBm)
{
    return 0;
}
}
