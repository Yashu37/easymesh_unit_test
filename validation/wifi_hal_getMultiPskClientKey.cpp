/*
 * HANDLER: wifi_hal_getMultiPskClientKey
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc_wifi_wrappers.c:298-305
 * (~/Desktop/G/rdk-wifi-hal).  With RDK_GMK_FIX 0 it is the VERBATIM original (reproduces the finding); with
 * RDK_GMK_FIX 1 it carries FIX 1 below.
 *
 * Scaffolding only: the REAL wifi_hal.h types (INT, mac_address_t, wifi_key_multi_psk_t) via hso_hal_ipc.h and
 * wifi_hal_dbg_print as the real macro over the log sink; the function under test is renamed
 * hwr_wifi_hal_getMultiPskClientKey (ipc_server_output harness files already define wifi_hal_* stubs).
 */
#include "hwr_defs.h"

/* 1 = with FIX 1, 0 = original unfixed function (set to 0 to reproduce the finding) */
#define RDK_GMK_FIX  0

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_getMultiPskClientKey hwr_wifi_hal_getMultiPskClientKey

//--------------------------------------------------------------------------------------------------
extern "C" {
INT wifi_hal_getMultiPskClientKey(  INT apIndex,
                                    mac_address_t mac,
                                    wifi_key_multi_psk_t *key)
{
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);
    wifi_hal_dbg_print("%s:%d: \tNOTICE: EMTPY FUNCTION.\n", __func__, __LINE__);
#if RDK_GMK_FIX
    /* FIX 1: this is a getter whose only output is *key.  The function stores nothing, so reporting success
     * handed the caller an unfilled wifi_key_multi_psk_t.  Report that the operation is not implemented. */
    return RETURN_ERR;
#else
    return 0;
#endif
}
}
