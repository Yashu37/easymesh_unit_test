/*
 * HANDLER: wifi_setApRetrylimit
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/banana-pi/platform.c:575 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub: it does not log,
 * does not use priv and returns 0.  There is no fix switch because there is no finding.  Renamed hwr_wifi_setApRetrylimit because the other platforms
 * define the same name.
 */
#include "hwr_srl.h"

#define wifi_setApRetrylimit hwr_wifi_setApRetrylimit

/* --- platform.c:575 --- */
extern "C" {
int wifi_setApRetrylimit(void *priv)
{
    return 0;
}
}
