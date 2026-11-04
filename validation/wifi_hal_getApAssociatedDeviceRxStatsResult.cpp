/*
 * HANDLER: wifi_hal_getApAssociatedDeviceRxStatsResult
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc_wifi_wrappers.c:104-115
 * (~/Desktop/G/rdk-wifi-hal).  With RDK_GRX_FIX 0 it is the VERBATIM original (reproduces the findings);
 * with RDK_GRX_FIX 1 it carries FIX 1..2 below.
 *
 * Scaffolding only: the REAL wifi_hal.h (hso_hal_ipc.h) declares wifi_getApAssociatedDeviceRxStatsResult and
 * wifi_associated_dev_rate_info_rx_stats_t; the platform function is a stub in the construct file; the debug
 * print is the real macro over the log sink; the function under test is renamed
 * hwr_wifi_hal_getApAssociatedDeviceRxStatsResult (the ipc_server_output harness already stubs the real name).
 */
#include "hwr_defs.h"

/* 1 = with FIX 1..2, 0 = original unfixed function (set to 0 to reproduce the findings) */
#define RDK_GRX_FIX  1

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_getApAssociatedDeviceRxStatsResult hwr_wifi_hal_getApAssociatedDeviceRxStatsResult

//--------------------------------------------------------------------------------------------------
extern "C" {
INT wifi_hal_getApAssociatedDeviceRxStatsResult(INT radioIndex,
                                                mac_address_t *clientMacAddress,
                                                wifi_associated_dev_rate_info_rx_stats_t **stats_array,
                                                UINT *output_array_size,
                                                ULLONG *handle)
{
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);

#if RDK_GRX_FIX
    /* FIX 1: all four pointers are read / written by the platform function; reject NULL ones. */
    if (clientMacAddress == NULL || stats_array == NULL || output_array_size == NULL || handle == NULL) {
        return RETURN_ERR;
    }
    /* FIX 2: the platform result was ignored and 0 returned, so a failure looked like success and the caller
     * read *stats_array / *output_array_size that the platform function never set. */
    return wifi_getApAssociatedDeviceRxStatsResult(radioIndex, clientMacAddress, stats_array, output_array_size, handle);
#else
    wifi_getApAssociatedDeviceRxStatsResult(radioIndex, clientMacAddress, stats_array, output_array_size, handle);

    return 0;
#endif
}
}
