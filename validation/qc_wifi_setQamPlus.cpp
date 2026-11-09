/*
 * HANDLER: wifi_setQamPlus (platform/qualcomm)
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/qualcomm/platform_ext.c:981-984 and platform_xer5.c:1242-1245 (identical) (~/Desktop/G/rdk-wifi-hal).  It is an empty stub: it does not log,
 * does not use radioIndex and returns 0 for every input (the QAM+ request is accepted and ignored: design note, same class as the banana-pi setter stubs, not counted).  No fix switch.
 * Renamed hwr_qc_wifi_setQamPlus because the other platforms define the same name.
 */
#include "hwr_qqp.h"

#define wifi_setQamPlus hwr_qc_wifi_setQamPlus

/* --- platform_ext.c:981-984 --- */
extern "C" {
int wifi_setQamPlus(void *radioIndex)
{
    return 0;
}
}
