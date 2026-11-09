/*
 * HANDLER: wifi_getDownStreamGroupAddress
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/intel/platform.c:1856-1859 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub that returns
 * RETURN_ERR for every input and never writes *disabled: the feature is explicitly reported as unsupported on this platform, so there is no finding.  There is no fix switch.  Renamed hwr_int_wifi_getDownStreamGroupAddress because the other
 * platforms define the same name.
 */
#include "hwr_idg.h"

#define wifi_getDownStreamGroupAddress hwr_int_wifi_getDownStreamGroupAddress

/* --- platform.c:1856-1859 --- */
extern "C" {
INT wifi_getDownStreamGroupAddress(INT apIndex, BOOL *disabled)
{
    return RETURN_ERR;
}
}
