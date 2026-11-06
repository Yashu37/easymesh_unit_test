/*
 * HANDLER: wifi_hal_getRadioNumberOfEntries
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc_wifi_wrappers.c:264-270 (~/Desktop/G/rdk-wifi-hal).  This
 * file holds ONLY THE FIXED code: it carries FIX 1 below.
 *
 * Scaffolding only: g_wifi_hal holds just num_radios (unsigned int, as in the real struct); the debug print is
 * the real macro over the log sink; the function under test is renamed hwr_wifi_hal_getRadioNumberOfEntries
 * (ipc_server_output already stubs the real name).
 */
#include "hwr_grn.h"


#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define g_wifi_hal            hwr_grn_world
#define wifi_hal_getRadioNumberOfEntries hwr_wifi_hal_getRadioNumberOfEntries

hwr_grn_world_t hwr_grn_world;

//--------------------------------------------------------------------------------------------------
extern "C" {
INT wifi_hal_getRadioNumberOfEntries(ULONG *output)
{
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);

    /* FIX 1: output is written unchecked. */
    if (output == NULL) {
        return RETURN_ERR;
    }
    *output = g_wifi_hal.num_radios;
    return 0;
}
}
