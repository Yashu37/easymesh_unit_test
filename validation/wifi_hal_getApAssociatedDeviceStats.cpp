/*
 * HANDLER: wifi_hal_getApAssociatedDeviceStats
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc_wifi_wrappers.c:65-75 (~/Desktop/G/rdk-wifi-hal).  This file
 * holds ONLY THE FIXED code: it carries FIX 1..2 below.
 *
 * Scaffolding only: the REAL wifi_hal.h (hso_hal_ipc.h) declares wifi_getApAssociatedDeviceStats, which is a
 * stub in the construct file (configurable return value, writes the output parameters like the platform
 * implementation does); wifi_hal_dbg_print is the real macro over the log sink; the function under test is
 * renamed hwr_wifi_hal_getApAssociatedDeviceStats (the ipc_server_output harness already stubs the real name).
 */
#include "hwr_defs.h"


#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_getApAssociatedDeviceStats hwr_wifi_hal_getApAssociatedDeviceStats

//--------------------------------------------------------------------------------------------------
extern "C" {
INT wifi_hal_getApAssociatedDeviceStats(INT apIndex,
                                        mac_address_t *clientMacAddress,
                                        wifi_associated_dev_stats_t *associated_dev_stats,
                                        ULLONG *handle)
{
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);

    /* FIX 1: the pointers are written by the platform function; reject NULL ones. */
    if (clientMacAddress == NULL || associated_dev_stats == NULL || handle == NULL) {
        return RETURN_ERR;
    }
    /* FIX 2: the platform result was ignored and 0 returned, so a failure looked like success and the caller
     * (ipc_server_output) went on to copy uninitialised statistics. */
    return wifi_getApAssociatedDeviceStats(apIndex, clientMacAddress, associated_dev_stats, handle);
}
}

