/*
 * HANDLER: wifi_getApDeviceRSSI (platform/raspberry-pi)
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/raspberry-pi/platform_pi.c:444-447 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub: it does not log,
 * does not read MAC, never writes *output_RSSI and returns 0 (success) for every input.  There is no fix switch.
 *
 * DESIGN NOTE (not counted, same class as the banana-pi getter stubs that return 0): the caller is told "success" but *output_RSSI is never set, so it keeps
 * whatever value it had.  Renamed hwr_rp_wifi_getApDeviceRSSI because other platforms may define the same name.
 */
#include "hwr_rrs.h"

#define wifi_getApDeviceRSSI hwr_rp_wifi_getApDeviceRSSI

/* --- platform_pi.c:444-447 --- */
extern "C" {
INT wifi_getApDeviceRSSI(INT ap_index, CHAR *MAC, INT *output_RSSI)
{
    return 0;
}
}
