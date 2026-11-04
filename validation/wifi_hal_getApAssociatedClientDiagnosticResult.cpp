/*
 * HANDLER: wifi_hal_getApAssociatedClientDiagnosticResult
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc_wifi_wrappers.c:225-234
 * (~/Desktop/G/rdk-wifi-hal).  With RDK_GCD_FIX 0 it is the VERBATIM original (reproduces the findings);
 * with RDK_GCD_FIX 1 it carries FIX 1..2 below.
 *
 * Scaffolding only: the REAL wifi_hal.h (hso_hal_ipc.h) declares wifi_getApAssociatedClientDiagnosticResult
 * (char * MAC argument) and wifi_associated_dev3_t; the platform function is a stub in the construct file; the
 * debug print is the real macro over the log sink; the function under test is renamed
 * hwr_wifi_hal_getApAssociatedClientDiagnosticResult (ipc_server_output already stubs the real name).
 */
#include "hwr_defs.h"

/* 1 = with FIX 1..2, 0 = original unfixed function (set to 0 to reproduce the findings) */
#define RDK_GCD_FIX  0

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_getApAssociatedClientDiagnosticResult hwr_wifi_hal_getApAssociatedClientDiagnosticResult

//--------------------------------------------------------------------------------------------------
extern "C" {
INT wifi_hal_getApAssociatedClientDiagnosticResult( INT apIndex,
                                                    char *mac_addr,
                                                    wifi_associated_dev3_t *dev_conn)
{
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);

#if RDK_GCD_FIX
    /* FIX 1: both pointers are used by the platform function; reject NULL ones. */
    if (mac_addr == NULL || dev_conn == NULL) {
        return RETURN_ERR;
    }
    /* FIX 2: the platform result was ignored and 0 returned, so a failure looked like success (the platform
     * implementations in rdk-wifi-hal return RETURN_ERR) and the caller (ipc_server_output) copied a
     * wifi_associated_dev3_t that was never filled. */
    return wifi_getApAssociatedClientDiagnosticResult(apIndex, mac_addr, dev_conn);
#else
    wifi_getApAssociatedClientDiagnosticResult(apIndex, mac_addr, dev_conn);

    return 0;
#endif
}
}
