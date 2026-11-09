/*
 * HANDLER: wifi_getDownStreamGroupAddress
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/banana-pi/platform.c:952 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub: it returns
 * 0 and never writes *disabled.  This file holds the ORIGINAL code: no fix is applied.  Renamed hwr_wifi_getDownStreamGroupAddress because the other
 * platforms define the same name.
 */
#include "hwr_gdg.h"

#define wifi_getDownStreamGroupAddress hwr_wifi_getDownStreamGroupAddress

/* --- platform.c:952 --- */
extern "C" {
INT wifi_getDownStreamGroupAddress(INT apIndex, BOOL *disabled)
{
    return 0;
}
}
