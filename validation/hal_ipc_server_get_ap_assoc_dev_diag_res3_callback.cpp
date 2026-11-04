/*
 * HANDLER: hal_ipc_server_get_ap_assoc_dev_diag_res3_callback
 *
 * Function copied VERBATIM from rdk-wifi-hal: hal_ipc/server/hal_ipc.c:790
 * (~/Desktop/G/rdk-wifi-hal).  No fixes, no edits.
 *
 * Scaffolding only:
 *  - app_get_ap_assoc_dev_diag_res3_t is the real callback typedef shape
 *    (wifi_hal_priv.h:636).
 *  - hal_ipc_server_callback_get_ap_assoc_dev_diag_res3 (the global the
 *    getter reads) is defined in the set_ap_assoc_dev_diag_res3 handler
 *    file and declared extern in common.h.
 *  - wifi_hal_dbg_print is the REAL macro (wifi_hal_priv.h:1339); the
 *    wifi_hal_print it expands to is the log-sink stub in the construct
 *    file of the set_ap_assoc_dev_diag_res3 harness (declared in common.h).
 */
#include <stdio.h>
#include <string.h>
#include "common.h"

typedef hipc_cb_t app_get_ap_assoc_dev_diag_res3_t;

#define wifi_hal_dbg_print(format, ...)  wifi_hal_print(WIFI_HAL_LOG_LVL_DEBUG, format, ##__VA_ARGS__)

/* --- copied verbatim from hal_ipc.c:790 --- */
app_get_ap_assoc_dev_diag_res3_t hal_ipc_server_get_ap_assoc_dev_diag_res3_callback(void)
{
    wifi_hal_dbg_print("%s: Enter.\n", __FUNCTION__);
    return hal_ipc_server_callback_get_ap_assoc_dev_diag_res3;
}
