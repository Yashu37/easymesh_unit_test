/*
 * HANDLER: wifi_hal_getRadioChannelStats
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc_wifi_wrappers.c:78-90
 * (~/Desktop/G/rdk-wifi-hal).  With RDK_GRC_FIX 0 it is the VERBATIM original (reproduces the findings);
 * with RDK_GRC_FIX 1 it carries FIX 1..2 below.
 *
 * Scaffolding only: the REAL wifi_hal.h (hso_hal_ipc.h) declares wifi_getRadioChannelStats and
 * HAL_IPC_RADIO_CHANNELS_MAX (64); the platform function is a stub in the construct file; the debug print is
 * the real macro over the log sink; the function under test is renamed hwr_wifi_hal_getRadioChannelStats
 * (the ipc_server_output harness already stubs the real name).
 */
#include "hwr_defs.h"

/* 1 = with FIX 1..2, 0 = original unfixed function (set to 0 to reproduce the findings) */
#define RDK_GRC_FIX  0

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_getRadioChannelStats hwr_wifi_hal_getRadioChannelStats

//--------------------------------------------------------------------------------------------------
extern "C" {
INT wifi_hal_getRadioChannelStats(INT radioIndex,
                                  wifi_channelStats_t *input_output_channelStats_array,
                                  INT array_size)
{
    wifi_hal_dbg_print("%s:%d: Enter. Array size %d\n", __func__, __LINE__, array_size);

#if RDK_GRC_FIX
    /* FIX 1: the platform function writes array_size entries into the array; reject a NULL array. */
    if (input_output_channelStats_array == NULL) {
        return RETURN_ERR;
    }
    /* FIX 2: only the upper bound was checked; a zero or negative array_size was forwarded to the platform
     * function (which uses it as an element count). */
    if (array_size <= 0) {
        return RETURN_ERR;
    }
#endif
    if (array_size > HAL_IPC_RADIO_CHANNELS_MAX){
        wifi_hal_dbg_print("%s:%d: array_size %d is too big. Truncate.\n", __func__, __LINE__, array_size);
        array_size = HAL_IPC_RADIO_CHANNELS_MAX;
    }

    return wifi_getRadioChannelStats(radioIndex, input_output_channelStats_array, array_size);
}
}
