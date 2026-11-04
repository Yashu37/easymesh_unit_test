/*
 * HANDLER: rdk_hal_ipc_exec
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc.c:826-940
 * (~/Desktop/G/rdk-wifi-hal).  With RDK_EXEC_FIX 0 it is the VERBATIM original
 * (reproduces the crashes); with RDK_EXEC_FIX 1 it carries FIX 1..4 below.
 *
 * Scaffolding only:
 *  - hal_ipc_node_t / hal_ipc_node_type_t are copied verbatim into common.h;
 *    hal_ipc_processor_desc_t has the real leading fields + len/scratch_buf/
 *    scratch_buf_size with padding standing in for the in/out unions
 *    (the real header needs the whole hostap header tree).
 *  - socket/bind/connect/setsockopt/send/close/unlink/free are redirected to
 *    stubs (construct file) so the function can be driven through every
 *    failure point without a real AF_UNIX server, and so the bytes handed to
 *    send() are actually read (an over-read of desc / scratch_buf aborts).
 *  - MAX_IPC_BUFF (hal_ipc.h:37 = 10240) is a runner variable so the
 *    "descriptor larger than max_size" chunk branch can also be exercised.
 *  - wifi_hal_error_print / wifi_hal_dbg_print are the REAL macros
 *    (wifi_hal_priv.h:1339-1341); wifi_hal_print is the log-sink stub.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "common.h"

/* 1 = with FIX 1..4, 0 = original unfixed function (set to 0 to reproduce the crashes) */
#define RDK_EXEC_FIX  1

#define MAX_IPC_BUFF  hipc_max_ipc_buff
#define wifi_hal_dbg_print(format, ...)    wifi_hal_print(WIFI_HAL_LOG_LVL_DEBUG, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)  wifi_hal_print(WIFI_HAL_LOG_LVL_ERROR, format, ##__VA_ARGS__)

#define socket      hipc_stub_socket
#define bind        hipc_stub_bind
#define connect     hipc_stub_connect
#define setsockopt  hipc_stub_setsockopt
#define send        hipc_stub_send
#define close       hipc_stub_close
#define unlink      hipc_stub_unlink
#define free        hipc_stub_free

/* --- copied verbatim from hal_ipc.c:826 --- */
int rdk_hal_ipc_exec(hal_ipc_node_t *p_ipc_node, hal_ipc_processor_desc_t *desc)
{
    socklen_t len;
    int cli_sock;
    int nbytes, target_bytes;
    unsigned int max_size = MAX_IPC_BUFF;
    struct sockaddr_un cli_sockaddr, srv_sockaddr;
    unsigned char *tmp;

#if RDK_EXEC_FIX
    /* FIX 1: reject NULL p_ipc_node / desc instead of dereferencing them. */
    if (p_ipc_node == NULL || desc == NULL) {
        wifi_hal_error_print("%s:%d: NULL parameter\n", __func__, __LINE__);
        return -1;
    }
#endif

    if ((cli_sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        wifi_hal_error_print("%s:%d:server socket create failed err: %d\n", __func__, __LINE__, errno);
        return -1;
    }

    cli_sockaddr.sun_family = AF_UNIX;
#if RDK_EXEC_FIX
    /* FIX 2: node_path is char[64]; copy at most that much and always NUL-terminate,
     * instead of an unbounded strcpy into the 108-byte sun_path. */
    strncpy(cli_sockaddr.sun_path, p_ipc_node->node_path, sizeof(p_ipc_node->node_path));
    cli_sockaddr.sun_path[sizeof(p_ipc_node->node_path)] = '\0';
    len = sizeof(cli_sockaddr);

    unlink(cli_sockaddr.sun_path);
#else
    strcpy(cli_sockaddr.sun_path, p_ipc_node->node_path);
    len = sizeof(cli_sockaddr);

    unlink(p_ipc_node->node_path);
#endif
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
#if RDK_EXEC_FIX
            /* FIX 3: assert(1) never fires, so an unsupported node type fell through to
             * connect() with an uninitialised srv_sockaddr.sun_path.  Fail instead. */
            close(cli_sock);
            return -1;
#else
            assert(1);
            break;
#endif
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
#if RDK_EXEC_FIX
    /* FIX 4: always use the send loop (not only when sizeof(desc) > max_size): a short
     * send() on the single-send path silently dropped the rest of the descriptor. */
    if (1) {
#else
    if (sizeof(hal_ipc_processor_desc_t) > max_size) {
#endif
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
