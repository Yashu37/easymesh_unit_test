/*
 * HANDLER: wifi_setP2PCrossConnect (platform/intel)
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/intel/platform.c:1850-1853 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub that returns
 * RETURN_ERR for every input: the feature is explipxtly reported as unsupported on this platform, so there is no finding and no fix switch.
 * (The banana-pi stub returns 0 here; the intel stub reports "unsupported" with RETURN_ERR.)  Renamed hwr_int_wifi_setP2PCrossConnect because the other platforms define
 * the same name.
 */
#include "hwr_ipx.h"

#define wifi_setP2PCrossConnect hwr_int_wifi_setP2PCrossConnect

/* --- platform.c:1850-1853 --- */
extern "C" {
INT wifi_setP2PCrossConnect(INT apIndex, BOOL disabled)
{
    return RETURN_ERR;
}
}
