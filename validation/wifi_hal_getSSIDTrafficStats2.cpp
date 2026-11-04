/*
 * HANDLER: wifi_hal_getSSIDTrafficStats2
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc_wifi_wrappers.c:93-101
 * (~/Desktop/G/rdk-wifi-hal).  With RDK_GTS_FIX 0 it is the VERBATIM original (reproduces the findings);
 * with RDK_GTS_FIX 1 it carries FIX 1..2 below.
 *
 * Scaffolding only: the REAL wifi_hal.h (hso_hal_ipc.h) declares wifi_getSSIDTrafficStats2 and
 * wifi_ssidTrafficStats2_t; the platform function is a stub in the construct file (configurable return
 * value, fills the structure); the debug print is the real macro over the log sink; the function under test
 * is renamed hwr_wifi_hal_getSSIDTrafficStats2 (the ipc_server_output harness already stubs the real name).
 */
#include "hwr_defs.h"

/* 1 = with FIX 1..2, 0 = original unfixed function (set to 0 to reproduce the findings) */
#define RDK_GTS_FIX  1

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_getSSIDTrafficStats2 hwr_wifi_hal_getSSIDTrafficStats2

//--------------------------------------------------------------------------------------------------
extern "C" {
INT wifi_hal_getSSIDTrafficStats2(  INT ssidIndex,
                                    wifi_ssidTrafficStats2_t *output_struct)
{
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);

#if RDK_GTS_FIX
    /* FIX 1: output_struct is written by the platform function; reject NULL. */
    if (output_struct == NULL) {
        return RETURN_ERR;
    }
    /* FIX 2: the platform result was ignored and 0 returned, so a failure looked like success and the caller
     * went on to use an output structure that was never filled. */
    return wifi_getSSIDTrafficStats2(ssidIndex, output_struct);
#else
    wifi_getSSIDTrafficStats2(ssidIndex, output_struct);

    return 0;
#endif
}
}
