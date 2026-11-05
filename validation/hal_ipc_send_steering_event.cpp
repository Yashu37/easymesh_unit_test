/*
 * HANDLER: hal_ipc_send_steering_event
 *
 * Function copied VERBATIM from rdk-wifi-hal: hal_ipc/server/server_hal_ipc.c:123-148 (~/Desktop/G/rdk-wifi-hal) - the steering
 * event callback registered with wifi_hal_steering_eventRegister().  It is static in the original, so it is reached
 * through the trampoline hwr_sse_call() below.  It has no logic of its own beyond chaining three collaborators, which
 * are copied VERBATIM so that the whole path is real:
 *  - ipc_client_notification_input, case hal_ipc_desc_type_steering_event (hal_ipc_processors.c:1158-1171), in a reduced
 *    switch (braces added around the case body).
 *  - rdk_hal_ipc_exec (hal_ipc.c:826-940).  This event has no scratch buffer, so the early-failure leak of tracker #78
 *    cannot occur.  socket / bind / connect / setsockopt / send / close / unlink are redirected to stubs (construct
 *    file) so every failure point can be driven and the bytes handed to send() are captured; malloc / free are
 *    counting stubs.
 *  - get_processor_desc / rdk_create_hal_ipc_node: stubs (construct file) returning a runner-owned descriptor whose
 *    ipc_processor[client_notification_input] is the copied processor, and the notification client node.
 * hal_ipc_processor_desc_t is the REAL packed descriptor (hso_hal_ipc.h); the prints are the real macros over the
 * log sink.  The function returns void: the runner derives "sent" from the bytes the stubbed send() received.
 */
#include "hwr_sse.h"
#include <errno.h>
#include <assert.h>
#include <stdio.h>

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_info_print(format, ...)   hwr_print(1, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)  hwr_print(2, format, ##__VA_ARGS__)
#define get_processor_desc         hwr_sse_get_processor_desc
#define rdk_create_hal_ipc_node    hwr_sse_create_node
#define rdk_hal_ipc_exec           sse_exec
#define malloc      hwr_sse_malloc
#define free        hwr_sse_free
#define socket      hwr_sse_socket
#define bind        hwr_sse_bind
#define connect     hwr_sse_connect
#define setsockopt  hwr_sse_setsockopt
#define send        hwr_sse_send
#define close       hwr_sse_close
#define unlink      hwr_sse_unlink

//--------------------------------------------------------------------------------------------------
/* --- copied verbatim from hal_ipc_processors.c (ipc_client_notification_input, one case) --- */
static int sni(struct hal_ipc_processor_desc *desc, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5)
{
    wifi_hal_dbg_print("%s:%d Enter: client notification input %s\n", __func__, __LINE__, desc->name);
    switch (desc->type) {
        case hal_ipc_desc_type_steering_event: {
            if (!arg1 || !arg2) {
                wifi_hal_dbg_print("%s:%d function %s require 2 arguments.\n", __func__, __LINE__, desc->name);
                return -1;
            }
            desc->in.steering_event_data.steering_group_index = *(unsigned int*) arg1;
            if (!memcpy((unsigned char*) &desc->in.steering_event_data.evt,
                       (unsigned char*) arg2,
                       sizeof(wifi_steering_event_t))) {
                wifi_hal_dbg_print("%s:%d FAIL memcpy %s wifi_steering_event_t\n", __func__, __LINE__, desc->name);
                return -1;
            }
            desc->len = sizeof(hal_ipc_processor_desc_t);
            break;
        }

        default:
            wifi_hal_dbg_print("%s:%d RFC API %s reached default.\n", __func__, __LINE__, desc->name);
            return -1;
    }
    return 0;
}
hal_ipc_processor_t hwr_sse_processor_fn = sni;

//--------------------------------------------------------------------------------------------------
/* --- copied verbatim from hal_ipc.c:826 --- */
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
        return -1;
    }

    cli_sockaddr.sun_family = AF_UNIX;
    strcpy(cli_sockaddr.sun_path, p_ipc_node->node_path);
    len = sizeof(cli_sockaddr);

    unlink(p_ipc_node->node_path);
    if (bind(cli_sock, (struct sockaddr *)&cli_sockaddr, len) == -1) {
        wifi_hal_error_print("%s:%d:client socket bind failed err: %d\n", __func__, __LINE__, errno);
        close(cli_sock);
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
        return -1;
    }

    if ((setsockopt(cli_sock, SOL_SOCKET, SO_SNDBUF, &max_size ,sizeof(int))) < 0) {
        wifi_hal_error_print("%s:%d:clientr socket size set failed err: %d\n", __func__, __LINE__, errno);
        close(cli_sock);
        return -1;
    }

    if (connect(cli_sock, (struct sockaddr *)&srv_sockaddr, len) == -1) {
        wifi_hal_error_print("%s:%d:connect failed err: %d\n", __func__, __LINE__, errno);
        close(cli_sock);
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
/* --- copied verbatim from server_hal_ipc.c:123 --- */
static void hal_ipc_send_steering_event(UINT steeringgroupIndex, wifi_steering_event_t *event)
{
    hal_ipc_node_t *node;
    hal_ipc_processor_t notification_input_func;
    hal_ipc_processor_desc_t *desc;

    desc  = get_processor_desc(hal_ipc_desc_type_steering_event);

    if ((node = rdk_create_hal_ipc_node(hal_ipc_node_type_notification_client)) == NULL) {
        wifi_hal_error_print("%s:%d: Failed to create notification client node\n", __func__, __LINE__);
        return;
    }

    notification_input_func = desc->ipc_processor[processor_type_ipc_client_notification_input];

    if ((notification_input_func != NULL) && (notification_input_func(desc, &steeringgroupIndex, event, NULL, NULL, NULL) != 0)) {
        wifi_hal_error_print("%s:%d: Client input processor failed\n", __func__, __LINE__);
        return;
    }
    wifi_hal_dbg_print("%s:%d: Steering event for apindex: %d and event type: %d for desc name %s: \n", __func__, __LINE__, event->apIndex, event->type, desc->name);

    if (rdk_hal_ipc_exec(node, desc) != 0) {
        wifi_hal_error_print("%s:%d: ipc  processor failed\n", __func__, __LINE__);
        return;
    }
}

extern "C" void hwr_sse_call(UINT steeringgroupIndex, wifi_steering_event_t *event)
{
    hal_ipc_send_steering_event(steeringgroupIndex, event);
}
