/*
 * HANDLER: wifi_setQamPlus
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/banana-pi/platform.c:570 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub: it does not log,
 * does not use priv and returns 0.  There is no fix switch because there is no finding.  Renamed hwr_wifi_setQamPlus because the other platforms
 * define the same name.
 */
#include "hwr_sqp.h"

#define wifi_setQamPlus hwr_wifi_setQamPlus

/* --- platform.c:570 --- */
extern "C" {
int wifi_setQamPlus(void *priv)
{
    return 0;
}
}
