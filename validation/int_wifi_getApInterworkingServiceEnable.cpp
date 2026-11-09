/*
 * HANDLER: wifi_getApInterworkingServiceEnable
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/intel/platform.c:1892-1895 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub that returns
 * RETURN_ERR for every input and never writes *output_bool: the feature is explicitly reported as unsupported on this platform, so there is no finding.  There is no fix switch.  Renamed hwr_int_wifi_getApInterworkingServiceEnable because the other
 * platforms define the same name.
 */
#include "hwr_igi.h"

#define wifi_getApInterworkingServiceEnable hwr_int_wifi_getApInterworkingServiceEnable

/* --- platform.c:1892-1895 --- */
extern "C" {
INT wifi_getApInterworkingServiceEnable(INT apIndex, BOOL *output_bool)
{
    return RETURN_ERR;
}
}
