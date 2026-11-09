/*
 * HANDLER: wifi_steering_eventRegister
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/banana-pi/platform.c:1004 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub: it does not log,
 * does not store or call event_cb and returns RETURN_OK.  There is no fix switch because there is no finding (no registry exists on this platform to
 * observe).  Renamed hwr_wifi_steering_eventRegister because the other platforms define the same name.
 */
#include "hwr_ser.h"

#define wifi_steering_eventRegister hwr_wifi_steering_eventRegister

/* --- platform.c:1004 --- */
extern "C" {
INT wifi_steering_eventRegister(wifi_steering_eventCB_t event_cb)
{
    return RETURN_OK;
}
}
