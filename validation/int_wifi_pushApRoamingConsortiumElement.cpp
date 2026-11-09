/*
 * HANDLER: wifi_pushApRoamingConsortiumElement (platform/intel)
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/intel/platform.c:1750-1753 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code: no fix
 * applied.  It is an empty stub that returns RETURN_ERR for every input and never touches infoElement: the platform reports pushing the Roaming Consortium
 * element as unsupported (the same class as the banana-pi wifi_getBssLoad / wifi_setApIsolationEnable stubs and intel wifi_getApInterworkingElement), so there is no finding and no fix switch.
 * Renamed hwr_int_wifi_pushApRoamingConsortiumElement because other harnesses may use the real name.
 */
#include "hwr_ipr.h"

#define wifi_pushApRoamingConsortiumElement hwr_int_wifi_pushApRoamingConsortiumElement

/* --- platform.c:1750-1753 --- */
extern "C" {
INT wifi_pushApRoamingConsortiumElement(INT apIndex, wifi_roamingConsortiumElement_t *infoElement)
{
    return RETURN_ERR;
}
}
