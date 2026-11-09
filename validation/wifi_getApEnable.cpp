/*
 * HANDLER: wifi_getApEnable
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/banana-pi/platform.c:909 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub: it returns
 * RETURN_OK and never writes *output_bool.  This file holds the ORIGINAL code: no fix is applied.  Renamed hwr_wifi_getApEnable because the other
 * platforms define the same name.
 */
#include "hwr_gae.h"

#define wifi_getApEnable hwr_wifi_getApEnable
#ifndef RETURN_OK
#define RETURN_OK 0
#endif

/* --- platform.c:909 --- */
extern "C" {
INT wifi_getApEnable(INT apIndex, BOOL *output_bool)
{
    return RETURN_OK;
}
}
