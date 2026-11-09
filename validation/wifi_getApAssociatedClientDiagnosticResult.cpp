/*
 * HANDLER: wifi_getApAssociatedClientDiagnosticResult
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/banana-pi/platform.c:978 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub that returns
 * RETURN_ERR for every input and never touches key / assoc: the feature is explicitly reported as unsupported on this platform, so there is no
 * finding and no fix switch.  Renamed hwr_wifi_getApAssociatedClientDiagnosticResult because the other platforms define the same name.
 */
#include "hwr_gcl.h"

#define wifi_getApAssociatedClientDiagnosticResult hwr_wifi_getApAssociatedClientDiagnosticResult

/* --- platform.c:978 --- */
extern "C" {
INT wifi_getApAssociatedClientDiagnosticResult(INT ap_index, char *key,wifi_associated_dev3_t *assoc)
{
    return RETURN_ERR;
}
}
