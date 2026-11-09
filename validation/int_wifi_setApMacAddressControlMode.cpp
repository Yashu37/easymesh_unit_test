/*
 * HANDLER: wifi_setApMacAddressControlMode (platform/intel)
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/intel/platform.c:1794-1797 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code: no fix
 * applied.  It is an empty stub that returns RETURN_OK (0) for every input: the MAC-filter mode request is accepted and ignored, nothing is stored,
 * nothing is logged and no pointer is involved (the same class as the banana-pi setter stubs, recorded as clean: design note, not counted).  No fix switch.
 * Renamed hwr_int_wifi_setApMacAddressControlMode because other harnesses may use the real name.
 */
#include "hwr_imc.h"

#define wifi_setApMacAddressControlMode hwr_int_wifi_setApMacAddressControlMode

/* --- platform.c:1794-1797 --- */
extern "C" {
INT wifi_setApMacAddressControlMode(INT apIndex, INT filterMode)
{
    return RETURN_OK;
}
}
