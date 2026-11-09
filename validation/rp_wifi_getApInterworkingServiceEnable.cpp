/*
 * HANDLER: wifi_getApInterworkingServiceEnable (platform/raspberry-pi)
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/raspberry-pi/platform_pi.c:742-745 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub that returns
 * 0 (success) for every input and never writes *output_bool.  There is no fix switch.
 *
 * DESIGN NOTE (not counted, same class as the banana-pi getter stubs that return 0): the caller is told "success" but *output_bool is never set, so it keeps
 * whatever value it had.  (The intel stub returns RETURN_ERR here.)  Renamed hwr_rp_wifi_getApInterworkingServiceEnable because the other platforms define the
 * same name.
 */
#include "hwr_rgi.h"

#define wifi_getApInterworkingServiceEnable hwr_rp_wifi_getApInterworkingServiceEnable

/* --- platform_pi.c:742-745 --- */
extern "C" {
INT wifi_getApInterworkingServiceEnable(INT apIndex, BOOL *output_bool)
{
    return 0;
}
}
