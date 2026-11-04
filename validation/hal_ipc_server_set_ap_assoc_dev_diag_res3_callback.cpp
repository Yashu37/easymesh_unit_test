/*
 * HANDLER: hal_ipc_server_set_ap_assoc_dev_diag_res3_callback
 *
 * Function copied VERBATIM from rdk-wifi-hal: hal_ipc/server/hal_ipc.c:761
 * (~/Desktop/G/rdk-wifi-hal).  No fixes, no edits.
 *
 * Scaffolding only (types/globals the real file gets from its headers):
 *  - app_get_ap_assoc_dev_diag_res3_t is the real callback typedef shape
 *    (wifi_hal_priv.h:636) with the opaque wifi_associated_dev3_t.
 *  - wifi_hal_dbg_print is the REAL macro (wifi_hal_priv.h:1339); the
 *    wifi_hal_print it expands to is a stub in the construct file that
 *    writes into a runner-owned, tail-poisoned slot.
 */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "common.h"

typedef hipc_cb_t   app_get_ap_assoc_dev_diag_res3_t;

/* wifi_hal_log_level_t / wifi_hal_print prototype: declared in common.h (shared with the log-sink stub) */
#define wifi_hal_dbg_print(format, ...)  wifi_hal_print(WIFI_HAL_LOG_LVL_DEBUG, format, ##__VA_ARGS__)

/* --- copied verbatim from hal_ipc.c:755-757 --- */
app_get_ap_assoc_dev_diag_res3_t hal_ipc_server_callback_get_ap_assoc_dev_diag_res3;
/* hal_ipc_server_callback_get_neighbor_ap2 is defined in the set_neighbor_ap2 handler file */
void *hal_ipc_server_callback_get_radio_channel_stats;   /* app_get_radio_channel_stats_t (opaque here) */

/* --- copied verbatim from hal_ipc.c:761 --- */
void hal_ipc_server_set_ap_assoc_dev_diag_res3_callback(app_get_ap_assoc_dev_diag_res3_t callback_get_ap_assoc_dev_diag_res3)
{
    // check for NULL pointer here?
    wifi_hal_dbg_print("%s: Enter.\n", __FUNCTION__);
    hal_ipc_server_callback_get_ap_assoc_dev_diag_res3 = callback_get_ap_assoc_dev_diag_res3;
}
