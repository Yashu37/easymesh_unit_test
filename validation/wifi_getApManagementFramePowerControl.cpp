/*
 * HANDLER: wifi_getApManagementFramePowerControl
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/banana-pi/platform.c:671 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub: it returns 0
 * (WIFI_HAL_SUCCESS) and never writes *output_dBm.  This file holds the ORIGINAL code: no fix is applied.  Renamed
 * hwr_wifi_getApManagementFramePowerControl because the other platforms define the same name.
 */
#include "hwr_gmp.h"

#define wifi_getApManagementFramePowerControl hwr_wifi_getApManagementFramePowerControl

/* --- platform.c:671 --- */
extern "C" {
INT wifi_getApManagementFramePowerControl(INT apIndex, INT *output_dBm)
{
    return 0;
}
}
