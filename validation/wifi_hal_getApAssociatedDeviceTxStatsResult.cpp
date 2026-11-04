/*
 * HANDLER: wifi_hal_getApAssociatedDeviceTxStatsResult
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc_wifi_wrappers.c:273-295
 * (~/Desktop/G/rdk-wifi-hal).  With RDK_GTX_FIX 0 it is the VERBATIM original (reproduces the findings);
 * with RDK_GTX_FIX 1 it carries FIX 1..2 below.
 *
 * Scaffolding only: the REAL wifi_hal.h (hso_hal_ipc.h) declares wifi_getApAssociatedDeviceTxStatsResult and
 * wifi_associated_dev_rate_info_tx_stats_t; the platform function is a stub in the construct file; the info
 * print is the real macro over the log sink; the function under test is renamed
 * hwr_wifi_hal_getApAssociatedDeviceTxStatsResult (ipc_server_output already stubs the real name).
 */
#include "hwr_defs.h"

/* 1 = with FIX 1..2, 0 = original unfixed function (set to 0 to reproduce the findings) */
#define RDK_GTX_FIX  0

#define wifi_hal_info_print(format, ...)   hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_getApAssociatedDeviceTxStatsResult hwr_wifi_hal_getApAssociatedDeviceTxStatsResult

//--------------------------------------------------------------------------------------------------
extern "C" {
INT wifi_hal_getApAssociatedDeviceTxStatsResult(INT radioIndex,
                                                mac_address_t *clientMacAddress,
                                                wifi_associated_dev_rate_info_tx_stats_t **stats_array,
                                                UINT *output_array_size,
                                                ULLONG *handle)
{
    int ret;

    wifi_hal_info_print("%s:%d: Enter...radio_index:%d\n", __func__, __LINE__, radioIndex);

#if RDK_GTX_FIX
    /* FIX 1: all four pointers are read / written by the platform function and *stats_array /
     * *output_array_size are dereferenced below; reject NULL ones. */
    if (clientMacAddress == NULL || stats_array == NULL || output_array_size == NULL || handle == NULL) {
        return RETURN_ERR;
    }
#endif
    ret = wifi_getApAssociatedDeviceTxStatsResult(radioIndex, clientMacAddress, stats_array, output_array_size, handle);
#if RDK_GTX_FIX
    /* FIX 2 (hardening): do not walk the array when the platform reported a size but returned no array. */
    if (ret == RETURN_OK && *stats_array != NULL) {
#else
    if (ret == RETURN_OK) {
#endif
        wifi_associated_dev_rate_info_tx_stats_t *stats_tx = *stats_array;
        int index = 0;
        for (index = 0; index < (int)*output_array_size; index++) {
            wifi_hal_info_print("%s:%d index:%d Radio_Index:%d num of statistics tx array:%d nss:%d mcs:%d bw:%d flags:%lld bytes:%lld msdus:%lld mpdus:%lld ppdus:%lld retries:%lld attempts:%lld\r\n", __func__, __LINE__, index, radioIndex,
                   *output_array_size, stats_tx->nss, stats_tx->mcs, stats_tx->bw, stats_tx->flags,
                   stats_tx->bytes, stats_tx->msdus, stats_tx->mpdus, stats_tx->ppdus, stats_tx->retries, stats_tx->attempts);
            stats_tx++;
        }
    }
    return ret;
}
}
