/*
 * HANDLER: wifi_setApRetrylimit (platform/xle)
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/xle/platform_xle.c:732-735 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub: it does not log,
 * does not use priv and returns 0 for every input (the retry-limit request is accepted and ignored: design note, same class as the banana-pi setter stubs, not counted).  No fix switch.
 * Renamed hwr_xl_wifi_setApRetrylimit because the other platforms define the same name.
 */
#include "hwr_xrl.h"

#define wifi_setApRetrylimit hwr_xl_wifi_setApRetrylimit

/* --- platform_xle.c:732-735 --- */
extern "C" {
int wifi_setApRetrylimit(void *priv)
{
    return 0;
}
}
