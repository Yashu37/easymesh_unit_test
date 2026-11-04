/*
 * HANDLER: hal_ipc_server_set_neighbor_ap2_callback
 *
 * Function copied VERBATIM from rdk-wifi-hal: hal_ipc/server/hal_ipc.c:768
 * (~/Desktop/G/rdk-wifi-hal).  No fixes, no edits.
 *
 * Scaffolding only:
 *  - app_get_neighbor_ap2_t is the real callback typedef shape
 *    (wifi_hal_priv.h:639), built on common.h's wifi_neighbor_ap2_t.
 *  - wifi_hal_dbg_print is the REAL macro (wifi_hal_priv.h:1339); the
 *    wifi_hal_print it expands to is the log-sink stub in the construct
 *    file (declared in common.h).
 */
#include <stdio.h>
#include <string.h>
#include "common.h"

typedef hipc_nb_cb_t app_get_neighbor_ap2_t;

#define wifi_hal_dbg_print(format, ...)  wifi_hal_print(WIFI_HAL_LOG_LVL_DEBUG, format, ##__VA_ARGS__)

/* --- copied verbatim from hal_ipc.c:756 --- */
app_get_neighbor_ap2_t hal_ipc_server_callback_get_neighbor_ap2;

/* --- copied verbatim from hal_ipc.c:768 --- */
void hal_ipc_server_set_neighbor_ap2_callback(app_get_neighbor_ap2_t callback_get_neighbor_ap2)
{
    // check for NULL pointer here?
    wifi_hal_dbg_print("%s: Enter.\n", __FUNCTION__);
    hal_ipc_server_callback_get_neighbor_ap2 = callback_get_neighbor_ap2;
}
