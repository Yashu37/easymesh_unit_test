/*
 * HANDLER: wifi_allow2G80211ax (platform/intel)
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/intel/platform.c:462-465 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code: no fix
 * applied.  It is an empty stub ("Stub for wave_api function, should be removed after implementation") that returns 0 for every input: the request to
 * allow 802.11ax on the 2.4 GHz radio is accepted and ignored, nothing is stored, nothing is logged and no argument is dereferenced (the only
 * parameter is a bool).  No finding, no fix switch.  Renamed hwr_int_wifi_allow2G80211ax because other harnesses may use the real name.
 */
#include "hwr_ia2.h"

#define wifi_allow2G80211ax hwr_int_wifi_allow2G80211ax

/* --- platform.c:462-465 --- */
extern "C" {
int wifi_allow2G80211ax(bool enable)
{
    return 0;
}
}
