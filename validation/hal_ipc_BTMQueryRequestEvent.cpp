/*
 * HANDLER: hal_ipc_BTMQueryRequestEvent
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/server_hal_ipc.c:28-57 (~/Desktop/G/rdk-wifi-hal) - the
 * BTM-query notification client the HAL registers with wifi_hal_BTMQueryRequest_callback_register().  It is
 * static in the original, so it is reached through the trampoline hwr_bqe_call() below.  With RDK_BQE_FIX 0 it
 * and its collaborators are the VERBATIM originals (reproduces the findings); with RDK_BQE_FIX 1 they carry
 * FIX 1..2 below.
 *
 * The function itself only chains three collaborators, and all three are copied so the whole path is real:
 *  - ipc_client_notification_input, case hal_ipc_btm_query_request_event (hal_ipc_processors.c:1207-1247), in a
 *    reduced switch (the case body is verbatim; braces added around it, see FIX 1).  Its missing arg5 check is
 *    tracker #24 and is kept applied here so this harness isolates the chain.  FIX 1 lives here.
 *  - rdk_hal_ipc_exec (hal_ipc.c:826-940), verbatim apart from the EXEC_ERR_CLEANUP(desc) lines that are no-ops
 *    with RDK_BQE_FIX 0 (FIX 2 lives here).  socket / bind / connect / setsockopt / send / close / unlink are
 *    redirected to stubs (construct file) so every failure point can be driven and the bytes handed to send()
 *    are captured; malloc / free are counting stubs, so a leaked scratch buffer is deterministic.
 *  - get_processor_desc / rdk_create_hal_ipc_node: stubs (construct file) that return a runner-owned descriptor
 *    whose ipc_processor[client_notification_input] is the copied processor, and the notification client node.
 * hal_ipc_processor_desc_t is the REAL packed descriptor (hso_hal_ipc.h); the prints are the real macros over
 * the log sink.
 */
#include "hwr_bqe.h"
#include <errno.h>
#include <assert.h>
#include <stdio.h>

/* 1 = with FIX 1..2, 0 = original unfixed code (set to 0 to reproduce the findings) */
#define RDK_BQE_FIX  1

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_info_print(format, ...)   hwr_print(1, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)  hwr_print(2, format, ##__VA_ARGS__)
#define get_processor_desc         hwr_bqe_get_processor_desc
#define rdk_create_hal_ipc_node    hwr_bqe_create_node
#define rdk_hal_ipc_exec           hwr_bqe_rdk_hal_ipc_exec
#define malloc      hwr_bqe_malloc
#define free        hwr_bqe_free
#define socket      hwr_bqe_socket
#define bind        hwr_bqe_bind
#define connect     hwr_bqe_connect
#define setsockopt  hwr_bqe_setsockopt
#define send        hwr_bqe_send
#define close       hwr_bqe_close
#define unlink      hwr_bqe_unlink

#if RDK_BQE_FIX
/* FIX 2: rdk_hal_ipc_exec frees desc->scratch_buf only after the descriptor was sent (and when the scratch send
 * fails).  Every earlier failure (socket / bind / setsockopt / connect / descriptor send, e.g. whenever the
 * notification server is not running) returned -1 with the scratch buffer that ipc_client_notification_input
 * malloc'd still allocated, and the caller (hal_ipc_BTMQueryRequestEvent) never frees it: one wifi_BTMQuery_t +
 * wifi_BTMRequest_t leaked per event. */
#define EXEC_ERR_CLEANUP(d) do { if ((d)->len > sizeof(hal_ipc_processor_desc_t) && (d)->scratch_buf) { free((d)->scratch_buf); (d)->scratch_buf = NULL; } } while (0)
#else
#define EXEC_ERR_CLEANUP(d)
#endif

//--------------------------------------------------------------------------------------------------
/* --- copied from hal_ipc_processors.c (ipc_client_notification_input, one case) --- */
static int hwr_bqe_ni(struct hal_ipc_processor_desc *desc, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5)
{
    wifi_hal_dbg_print("%s:%d Enter: client notification input %s\n", __func__, __LINE__, desc->name);
    switch (desc->type) {
        case hal_ipc_btm_query_request_event: {
            /* tracker #24 (already fixed in the ipc_client_notification_input harness): arg5 is copied below, so it is checked
             * here as well; kept applied so that this harness isolates the BTMQueryRequestEvent chain. */
            if (!arg1 || !arg2 || !arg3 || !arg4 || !arg5) {
                wifi_hal_dbg_print("%s:%d function %s require 4 arguments.\n", __func__, __LINE__, desc->name);
                return -1;
            }
            desc->in.btm_query_request_event_data.apIndex = *(unsigned int*) arg1;
            wifi_hal_info_print("%s:%d:: %s() ap_index:%d\n", __func__, __LINE__, desc->name, desc->in.btm_query_request_event_data.apIndex);
#if RDK_BQE_FIX
            /* FIX 1: the caller (wifi_hal_wnm_rrm.c, non-PHASE2 build) passes peerMac as a "xx:xx:xx:xx:xx:xx" STRING
             * (wrapper parameter CHAR *peerMac), but sizeof(mac_address_t) = 6 raw bytes of that string were copied
             * as the MAC (the first six characters "aa:bb:", and an over-read for a string shorter than 6 bytes).
             * Parse it like the btm_response_event case does: read at most 17 characters and reject a string that
             * does not parse into 6 bytes. */
            {
            mac_address_t sta_mac;
            char mac_str[18];
            size_t mac_len = strnlen((const char *)arg2, sizeof(mac_str) - 1);
            memcpy(mac_str, arg2, mac_len);
            mac_str[mac_len] = 0;
            memset(sta_mac, 0, sizeof(mac_address_t));
            if (sscanf(mac_str, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", &sta_mac[0], &sta_mac[1], &sta_mac[2],&sta_mac[3], &sta_mac[4], &sta_mac[5]) != 6) {
                wifi_hal_dbg_print("%s:%d FAIL %s invalid peer mac string\n", __func__, __LINE__, desc->name);
                return -1;
            }
            memcpy((unsigned char*) &desc->in.btm_query_request_event_data.peerMac, sta_mac, sizeof(mac_address_t));
            }
#else
            if (!memcpy((unsigned char*) &desc->in.btm_query_request_event_data.peerMac,
                        (unsigned char*) arg2,
                        sizeof(mac_address_t))) {
                wifi_hal_dbg_print("%s:%d FAIL memcpy %s mac_address_t\n", __func__, __LINE__, desc->name);
                return -1;
            }
#endif
            desc->in.btm_query_request_event_data.inMemSize = *(unsigned int*) arg4;
            
            desc->scratch_buf = (unsigned char*) malloc(sizeof(wifi_BTMQuery_t) + sizeof(wifi_BTMRequest_t));
            if (!desc->scratch_buf) {
                wifi_hal_dbg_print("%s:%d FAIL desc->scratch_buf malloc %s for wifi_BTMQuery_t and wifi_BTMRequest_t\n", __func__, __LINE__, desc->name);
                return -1;
            }

            if (!memcpy((unsigned char*) desc->scratch_buf,
                        (unsigned char*) arg3,
                        sizeof(wifi_BTMQuery_t))) {
                wifi_hal_dbg_print("%s:%d FAIL memcpy %s wifi_BTMResponse_t\n", __func__, __LINE__, desc->name);
                free(desc->scratch_buf); 
                return -1;
            }

            if (!memcpy((unsigned char*) (desc->scratch_buf + sizeof(wifi_BTMQuery_t)),
                        (unsigned char*) arg5,
                        sizeof(wifi_BTMRequest_t))) {
                wifi_hal_dbg_print("%s:%d FAIL memcpy %s wifi_BTMResponse_t\n", __func__, __LINE__, desc->name);
                free(desc->scratch_buf); 
                return -1;
            }
            desc->scratch_buf_size = sizeof(wifi_BTMQuery_t) + sizeof(wifi_BTMRequest_t);
            desc->len = sizeof(hal_ipc_processor_desc_t) + desc->scratch_buf_size;

            break;
        }

        default:
            wifi_hal_dbg_print("%s:%d RFC API %s reached default.\n", __func__, __LINE__, desc->name);
            return -1;
    }
    return 0;
}
hal_ipc_processor_t hwr_bqe_processor_fn = hwr_bqe_ni;

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
/* --- copied from server_hal_ipc.c:28 --- */
static INT hal_ipc_BTMQueryRequestEvent(UINT apIndex,
                                        CHAR *peerMac,
                                        wifi_BTMQuery_t *query,
                                        UINT inMemSize,
                                        wifi_BTMRequest_t *request)
{
    hal_ipc_node_t *node;
    hal_ipc_processor_t notification_input_func;
    hal_ipc_processor_desc_t *desc;

    desc  = get_processor_desc(hal_ipc_btm_query_request_event);

    if ((node = rdk_create_hal_ipc_node(hal_ipc_node_type_notification_client)) == NULL) {
        wifi_hal_error_print("%s:%d: Failed to create notification client node\n", __func__, __LINE__);
        return -1;
    }

    notification_input_func = desc->ipc_processor[processor_type_ipc_client_notification_input];

    if ((notification_input_func != NULL) && (notification_input_func(desc, &apIndex, peerMac, query, &inMemSize, request) != 0)) {
        wifi_hal_error_print("%s:%d: Client input processor failed\n", __func__, __LINE__);
        return -1;
    }

    if (rdk_hal_ipc_exec(node, desc) != 0) {
        wifi_hal_error_print("%s:%d: ipc  processor failed\n", __func__, __LINE__);
        return -1;
    }
    return 0;
}

extern "C" INT hwr_bqe_call(UINT apIndex, CHAR *peerMac, wifi_BTMQuery_t *query, UINT inMemSize, wifi_BTMRequest_t *request)
{
    return hal_ipc_BTMQueryRequestEvent(apIndex, peerMac, query, inMemSize, request);
}
