/*
 * HANDLER: hal_ipc_RMBeaconReportEvent
 *
 * Function copied VERBATIM from rdk-wifi-hal: hal_ipc/server/server_hal_ipc.c:88-117 (~/Desktop/G/rdk-wifi-hal) - the
 * RM beacon report notification client the HAL registers with wifi_hal_RMBeaconRequestCallbackRegister().  It is
 * static in the original, so it is reached through the trampoline hwr_rmb_call() below.  It has no logic of its
 * own beyond chaining three collaborators, which are copied so that the whole path is real:
 *  - ipc_client_notification_input, case hal_ipc_rm_beacon_report_event (hal_ipc_processors.c:1177-1206), VERBATIM, in a
 *    reduced switch (braces added around the case body).
 *  - rdk_hal_ipc_exec (hal_ipc.c:826-940), verbatim apart from the EXEC_ERR_CLEANUP(desc) lines.  This event carries a
 *    scratch buffer, so it is hit by the early-failure leak of tracker #78 (found with hal_ipc_BTMQueryRequestEvent,
 *    root cause in rdk_hal_ipc_exec): RDK_RMB_FIX 1 keeps that fix applied so this harness does not count the same
 *    finding twice; set it to 0 to see the leak again through this function.  socket / bind / connect / setsockopt /
 *    send / close / unlink are redirected to stubs (construct file) so every failure point can be driven and the
 *    bytes handed to send() are captured; malloc / free are counting stubs.
 *  - get_processor_desc / rdk_create_hal_ipc_node: stubs (construct file) returning a runner-owned descriptor whose
 *    ipc_processor[client_notification_input] is the copied processor, and the notification client node.
 * hal_ipc_processor_desc_t is the REAL packed descriptor (hso_hal_ipc.h); the prints are the real macros over the
 * log sink.
 */
#include "hwr_rmb.h"
#include <errno.h>
#include <assert.h>
#include <stdio.h>

/* 1 = rdk_hal_ipc_exec carries the fix of tracker #78, 0 = verbatim original (leaks the scratch buffer on early failures) */
#define RDK_RMB_FIX  1

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_info_print(format, ...)   hwr_print(1, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)  hwr_print(2, format, ##__VA_ARGS__)
#define get_processor_desc         hwr_rmb_get_processor_desc
#define rdk_create_hal_ipc_node    hwr_rmb_create_node
#define rdk_hal_ipc_exec           hwr_rmb_rdk_hal_ipc_exec
#define malloc      hwr_rmb_malloc
#define free        hwr_rmb_free
#define socket      hwr_rmb_socket
#define bind        hwr_rmb_bind
#define connect     hwr_rmb_connect
#define setsockopt  hwr_rmb_setsockopt
#define send        hwr_rmb_send
#define close       hwr_rmb_close
#define unlink      hwr_rmb_unlink

#if RDK_RMB_FIX
/* FIX (tracker #78, same root cause as in hal_ipc_RMBeaconReportEvent): rdk_hal_ipc_exec frees desc->scratch_buf only after the descriptor was sent (and when the scratch send
 * fails).  Every earlier failure (socket / bind / setsockopt / connect / descriptor send, e.g. whenever the
 * notification server is not running) returned -1 with the scratch buffer that ipc_client_notification_input
 * malloc'd still allocated, and the caller (hal_ipc_RMBeaconReportEvent) never frees it: one wifi_BTMQuery_t +
 * wifi_BTMRequest_t leaked per event. */
#define EXEC_ERR_CLEANUP(d) do { if ((d)->len > sizeof(hal_ipc_processor_desc_t) && (d)->scratch_buf) { free((d)->scratch_buf); (d)->scratch_buf = NULL; } } while (0)
#else
#define EXEC_ERR_CLEANUP(d)
#endif


//--------------------------------------------------------------------------------------------------
/* --- copied verbatim from hal_ipc_processors.c (ipc_client_notification_input, one case) --- */
static int hwr_rmb_ni(struct hal_ipc_processor_desc *desc, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5)
{
    wifi_hal_dbg_print("%s:%d Enter: client notification input %s\n", __func__, __LINE__, desc->name);
    switch (desc->type) {
        case hal_ipc_rm_beacon_report_event: {
            if (!arg1 || !arg2 || !arg3 || !arg4) {
                wifi_hal_dbg_print("%s:%d function %s require 4 arguments.\n", __func__, __LINE__, desc->name);
                return -1;
            }
            
            desc->in.rm_beacon_report_event_data.apIndex = *(unsigned int*) arg1;
            wifi_hal_info_print("%s:%d:: %s() ap_index:%d\n", __func__, __LINE__, desc->name, desc->in.rm_beacon_report_event_data.apIndex);

            desc->scratch_buf = (unsigned char*) malloc(sizeof(wifi_BeaconReport_t));
            if (!desc->scratch_buf) {
                wifi_hal_dbg_print("%s:%d FAIL desc->scratch_buf malloc %s for wifi_BeaconReport_t\n", __func__, __LINE__, desc->name);
                return -1;
            }

            if (!memcpy((unsigned char*) desc->scratch_buf,
                        (unsigned char*) arg2,
                        sizeof(wifi_BeaconReport_t))) {
                wifi_hal_dbg_print("%s:%d FAIL memcpy %s wifi_BeaconReport_t\n", __func__, __LINE__, desc->name);
                free(desc->scratch_buf); 
                return -1;
            }

            desc->in.rm_beacon_report_event_data.out_array_size = *(unsigned int*) arg3;
            desc->in.rm_beacon_report_event_data.out_DialogToken = *(unsigned char*) arg4;

            desc->scratch_buf_size = sizeof(wifi_BeaconReport_t);
            desc->len = sizeof(hal_ipc_processor_desc_t) + desc->scratch_buf_size;
            break;
        }

        default:
            wifi_hal_dbg_print("%s:%d RFC API %s reached default.\n", __func__, __LINE__, desc->name);
            return -1;
    }
    return 0;
}
hal_ipc_processor_t hwr_rmb_processor_fn = hwr_rmb_ni;

//--------------------------------------------------------------------------------------------------
/* --- copied from hal_ipc.c:826 --- */
int rdk_hal_ipc_exec(hal_ipc_node_t *p_ipc_node, hal_ipc_processor_desc_t *desc)
{
    socklen_t len;
    int cli_sock;
    int nbytes, target_bytes;
    unsigned int max_size = MAX_IPC_BUFF;
    struct sockaddr_un cli_sockaddr, srv_sockaddr;
    unsigned char *tmp;

    if ((cli_sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        wifi_hal_error_print("%s:%d:server socket create failed err: %d\n", __func__, __LINE__, errno);
        EXEC_ERR_CLEANUP(desc);
        return -1;
    }

    cli_sockaddr.sun_family = AF_UNIX;
    strcpy(cli_sockaddr.sun_path, p_ipc_node->node_path);
    len = sizeof(cli_sockaddr);

    unlink(p_ipc_node->node_path);
    if (bind(cli_sock, (struct sockaddr *)&cli_sockaddr, len) == -1) {
        wifi_hal_error_print("%s:%d:client socket bind failed err: %d\n", __func__, __LINE__, errno);
        close(cli_sock);
        EXEC_ERR_CLEANUP(desc);
        return -1;
    }

    srv_sockaddr.sun_family = AF_UNIX;

    switch (p_ipc_node->type) {
        case hal_ipc_node_type_sync_call_sm_client:
        case hal_ipc_node_type_sync_call_bm_client:
            strcpy(srv_sockaddr.sun_path, "/tmp/hal_sync_server");
            break;

        case hal_ipc_node_type_notification_client:
            strcpy(srv_sockaddr.sun_path, "/tmp/hal_notification_server");
            break;

        default:
            wifi_hal_error_print("%s:%d: Assert!!!.\n", __func__, __LINE__);
            assert(1);
            break;
    }

    if ((setsockopt(cli_sock, SOL_SOCKET, SO_RCVBUF, &max_size ,sizeof(int))) < 0) {
        wifi_hal_error_print("%s:%d:clientr socket size set failed err: %d\n", __func__, __LINE__, errno);
        close(cli_sock);
        EXEC_ERR_CLEANUP(desc);
        return -1;
    }

    if ((setsockopt(cli_sock, SOL_SOCKET, SO_SNDBUF, &max_size ,sizeof(int))) < 0) {
        wifi_hal_error_print("%s:%d:clientr socket size set failed err: %d\n", __func__, __LINE__, errno);
        close(cli_sock);
        EXEC_ERR_CLEANUP(desc);
        return -1;
    }

    if (connect(cli_sock, (struct sockaddr *)&srv_sockaddr, len) == -1) {
        wifi_hal_error_print("%s:%d:connect failed err: %d\n", __func__, __LINE__, errno);
        close(cli_sock);
        EXEC_ERR_CLEANUP(desc);
        return -1;
    }

    wifi_hal_dbg_print("%s:%d: sending desc %s struct of size bytes %d\n",
            __func__, __LINE__, desc->name, desc->len);

    ///************************************************************************///
    ///     SEND DATA TO SERVER FOR PROCESSING                                 ///
    ///************************************************************************///
    tmp = (unsigned char *)desc;
    if (sizeof(hal_ipc_processor_desc_t) > max_size) {
        nbytes = 0;
        target_bytes = 0;

        while (target_bytes < sizeof(hal_ipc_processor_desc_t)) {
            if ((nbytes = send(cli_sock, tmp, ((sizeof(hal_ipc_processor_desc_t) - target_bytes) > max_size) ? max_size : (sizeof(hal_ipc_processor_desc_t) - target_bytes), 0)) == -1) {
                wifi_hal_error_print("%s:%d:sending desc in chunks failed err: %d\n", __func__, __LINE__, errno);
                close(cli_sock);
                EXEC_ERR_CLEANUP(desc);
                return -1;
            }
            tmp += nbytes;
            target_bytes += nbytes;
        }
        nbytes = target_bytes;
    }
    else {
        if ((nbytes = send(cli_sock, tmp, sizeof(hal_ipc_processor_desc_t), 0)) == -1) {
            wifi_hal_error_print("%s:%d:sending desc failed err: %d\n", __func__, __LINE__, errno);
            close(cli_sock);
            EXEC_ERR_CLEANUP(desc);
            return -1;
        }
    }

    target_bytes = 0;
    nbytes = 0;

    if (desc->len > sizeof(hal_ipc_processor_desc_t)) {
        tmp = desc->scratch_buf;
        while (target_bytes < desc->scratch_buf_size) {
            if ((nbytes = send(cli_sock, tmp, ((desc->scratch_buf_size - target_bytes) > max_size) ? max_size : desc->scratch_buf_size - target_bytes, 0)) == -1) {
                wifi_hal_error_print("%s:%d:sending desc in chunks failed err: %d\n", __func__, __LINE__, errno);
                close(cli_sock);
                free(desc->scratch_buf);
                return -1;
            }
            tmp += nbytes;
            target_bytes += nbytes;
        }
        free(desc->scratch_buf);
    }

    wifi_hal_dbg_print("%s:%d: sent %d bytes\n", __func__, __LINE__, desc->len);

    close(cli_sock);

    return 0;
}

//--------------------------------------------------------------------------------------------------
/* --- copied verbatim from server_hal_ipc.c:88 --- */
static INT hal_ipc_RMBeaconReportEvent( UINT                apIndex,
                                        wifi_BeaconReport_t *out_struct,
                                        UINT                *out_array_size,
                                        UCHAR               *out_DialogToken)
{
    hal_ipc_node_t *node;
    hal_ipc_processor_t notification_input_func;
    hal_ipc_processor_desc_t *desc;

    desc  = get_processor_desc(hal_ipc_rm_beacon_report_event);

    if ((node = rdk_create_hal_ipc_node(hal_ipc_node_type_notification_client)) == NULL) {
        wifi_hal_error_print("%s:%d: Failed to create notification client node\n", __func__, __LINE__);
        return -1;
    }

    notification_input_func = desc->ipc_processor[processor_type_ipc_client_notification_input];

    if ((notification_input_func != NULL) && (notification_input_func(desc, &apIndex, out_struct, out_array_size, out_DialogToken, NULL) != 0)) {
        wifi_hal_error_print("%s:%d: Client input processor failed\n", __func__, __LINE__);
        return -1;
    }

    if (rdk_hal_ipc_exec(node, desc) != 0) {
        wifi_hal_error_print("%s:%d: ipc  processor failed\n", __func__, __LINE__);
        return -1;
    }

    return 0;
}

extern "C" INT hwr_rmb_call(UINT apIndex, wifi_BeaconReport_t *out_struct, UINT *out_array_size, UCHAR *out_DialogToken)
{
    return hal_ipc_RMBeaconReportEvent(apIndex, out_struct, out_array_size, out_DialogToken);
}
