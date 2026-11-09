/*
 * HANDLER: wifi_applyGASConfiguration (platform/intel)
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/intel/platform.c:1868-1871 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub: it does not log,
 * does not use input_struct and returns RETURN_ERR (-1) (the banana-pi stub returns 0): the feature is reported as unsupported, no finding, no fix switch.
 * Renamed hwr_int_wifi_applyGASConfiguration because the other platforms define the same name.
 */
#include "hwr_iga.h"

#define wifi_applyGASConfiguration hwr_int_wifi_applyGASConfiguration

/* --- platform.c:1868-1871 --- */
extern "C" {
INT wifi_applyGASConfiguration(wifi_GASConfiguration_t *input_struct)
{
    return RETURN_ERR;
}
}
