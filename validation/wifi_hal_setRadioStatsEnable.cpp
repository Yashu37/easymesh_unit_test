/*
 * HANDLER: wifi_hal_setRadioStatsEnable
 *
 * Function copied VERBATIM from rdk-wifi-hal: hal_ipc/server/hal_ipc_wifi_wrappers.c:25-32
 * (~/Desktop/G/rdk-wifi-hal).  No fixes, no edits.
 *
 * Scaffolding only: the REAL wifi_hal.h types (INT, BOOL) via hso_hal_ipc.h, and wifi_hal_dbg_print
 * as the real macro over a log sink (hwr_print).
 */
#include "hso_hal_ipc.h"

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
/* the ipc_server_output harness already defines stubs named wifi_hal_*: the function under test is renamed here */
#define wifi_hal_setRadioStatsEnable hwr_wifi_hal_setRadioStatsEnable
extern "C" void hwr_print(int level, const char *format, ...) __attribute__((format(printf, 2, 3)));

//--------------------------------------------------------------------------------------------------
extern "C" {
INT wifi_hal_setRadioStatsEnable(   INT radioIndex,
                                    BOOL enabled)
{
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);
    wifi_hal_dbg_print("%s:%d: \tNOTICE: EMTPY FUNCTION.\n", __func__, __LINE__);

    return 0;
}
}
