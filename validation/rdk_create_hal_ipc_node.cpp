/*
 * HANDLER: rdk_create_hal_ipc_node
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc.c:1190-1222
 * (~/Desktop/G/rdk-wifi-hal).  With RDK_CRE_FIX 0 it is the VERBATIM original
 * (reproduces the finding); with RDK_CRE_FIX 1 it carries FIX 1 below.
 *
 * Scaffolding only:
 *  - g_ipc_node[hal_ipc_node_type_max] is a runner-owned slab (hcre_gnode_slab,
 *    tail poisoned by the runner) accessed through the g_ipc_node macro.
 *  - pthread_create is redirected to a stub that records its arguments (no
 *    thread is started) and can be told to fail.
 *  - rdk_hal_server_func is static in the original and is only needed as the
 *    start routine pointer: a dummy with the same name stands in for it.
 *  - wifi_hal_dbg_print is the REAL macro; wifi_hal_print is the log-sink stub.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "common.h"

/* 1 = with FIX 1, 0 = original unfixed function (set to 0 to reproduce the finding) */
#define RDK_CRE_FIX  1

#define wifi_hal_dbg_print(format, ...)    wifi_hal_print(WIFI_HAL_LOG_LVL_DEBUG, format, ##__VA_ARGS__)
#define g_ipc_node     ((hal_ipc_node_t *)hcre_gnode_slab)
#define pthread_create hcre_stub_pthread_create

static void *rdk_hal_server_func(void *arg) { (void)arg; return NULL; }   /* scaffold: only its address is used */
void *hcre_server_func_addr(void) { return (void *)rdk_hal_server_func; }

/* --- copied from hal_ipc.c:1190 --- */
hal_ipc_node_t *rdk_create_hal_ipc_node(hal_ipc_node_type_t type)
{
    hal_ipc_node_t *node;

#if RDK_CRE_FIX
    /* FIX 1: type indexes g_ipc_node[] and is written through (node->type = type) BEFORE it is
     * validated; any value outside [0, hal_ipc_node_type_max) reads/writes outside the array. */
    if ((int)type < 0 || type >= hal_ipc_node_type_max) {
        wifi_hal_dbg_print("%s:%d: Invalid node type %d.\n", __func__, __LINE__, (int)type);
        return NULL;
    }
#endif

    // always return the node based on enumeration of node type which is also the index of the array
    node = &g_ipc_node[type];

    node->type = type;

    switch (type) {
        case hal_ipc_node_type_sync_call_server:
            strcpy(node->node_path, "/tmp/hal_sync_server");
            break;

        case hal_ipc_node_type_notification_client:
            strcpy(node->node_path, "/tmp/hal_notification_client");
            break;

        case hal_ipc_node_type_sync_call_bm_client:
        case hal_ipc_node_type_sync_call_sm_client:
        case hal_ipc_node_type_notification_server:
        default:
            wifi_hal_dbg_print("%s:%d: Invalid node type for server.\n", __func__, __LINE__);
            return NULL;
    }

    if ((type == hal_ipc_node_type_sync_call_server) && (pthread_create(&node->listener_tid, NULL, rdk_hal_server_func, node) != 0)) {
        wifi_hal_dbg_print("%s:%d: Failed to create HAL server ipc node and start server.\n", __func__, __LINE__);
        return NULL;
    }

    return node;
}
