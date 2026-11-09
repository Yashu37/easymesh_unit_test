/*
 * HANDLER: wifi_getRadioChannel (platform/raspberry-pi)
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/raspberry-pi/platform_pi.c:638-641 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub: it does not log,
 * never writes *output_ulong and returns 0 (success) for every input.  There is no fix switch.  (The intel version looks the radio up and writes the channel;
 * it had a NULL-output crash, #133: this stub never touches the pointer.)
 *
 * DESIGN NOTE (not counted, same class as the banana-pi getter stubs that return 0): the caller is told "success" but *output_ulong is never set, so it keeps
 * whatever value it had.  Renamed hwr_rp_wifi_getRadioChannel because other platforms define the same name.
 */
#include "hwr_rgc.h"

#define wifi_getRadioChannel hwr_rp_wifi_getRadioChannel

/* --- platform_pi.c:638-641 --- */
extern "C" {
INT wifi_getRadioChannel(INT radioIndex, ULONG *output_ulong)
{
    return 0;
}
}
