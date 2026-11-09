/*
 * HANDLER: wifi_getApInterworkingElement (platform/intel)
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/intel/platform.c:1745-1748 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code: no fix
 * applied.  It is an empty stub that returns RETURN_ERR for every input and never touches output_struct: the platform reports the Interworking element
 * as unsupported (the same class as the banana-pi wifi_getBssLoad / wifi_setApIsolationEnable stubs), so there is no finding and no fix switch.
 * Renamed hwr_int_wifi_getApInterworkingElement because other harnesses may use the real name.
 */
#include "hwr_iie.h"

#define wifi_getApInterworkingElement hwr_int_wifi_getApInterworkingElement

/* --- platform.c:1745-1748 --- */
extern "C" {
INT wifi_getApInterworkingElement(INT apIndex, wifi_InterworkingElement_t *output_struct)
{
    return RETURN_ERR;
}
}
