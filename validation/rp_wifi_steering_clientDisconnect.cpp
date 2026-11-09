/*
 * HANDLER: wifi_steering_clientDisconnect (platform/raspberry-pi)
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/raspberry-pi/platform_pi.c:686-690 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub: it does not log,
 * does not read client_mac and returns 0 (success) for every input.  There is no fix switch.
 *
 * DESIGN NOTE (not counted, same class as the banana-pi setter stubs that return 0): the caller is told the client was disconnected but nothing is done.
 * Renamed hwr_rp_wifi_steering_clientDisconnect because other platforms / the hal_ipc harness define the same name.
 */
#include "hwr_rcd.h"

#define wifi_steering_clientDisconnect hwr_rp_wifi_steering_clientDisconnect

/* --- platform_pi.c:686-690 --- */
extern "C" {
INT wifi_steering_clientDisconnect(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac,
    wifi_disconnectType_t type, UINT reason)
{
    return 0;
}
}
