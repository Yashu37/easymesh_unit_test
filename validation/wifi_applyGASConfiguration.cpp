/*
 * HANDLER: wifi_applyGASConfiguration
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/banana-pi/platform.c:999 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub: it does not log,
 * does not use input_struct and returns 0.  There is no fix switch because there is no finding.  Renamed hwr_wifi_applyGASConfiguration because the other platforms
 * define the same name.
 */
#include "hwr_aga.h"

#define wifi_applyGASConfiguration hwr_wifi_applyGASConfiguration

/* --- platform.c:999 --- */
extern "C" {
INT wifi_applyGASConfiguration(wifi_GASConfiguration_t *input_struct)
{
    return 0;
}
}
