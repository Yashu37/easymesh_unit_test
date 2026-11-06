/*
 * HANDLER: rdk_hal_server_func
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc.c:943-1187 (~/Desktop/G/rdk-wifi-hal).  This file holds ONLY
 * THE FIXED code: it carries FIX 1..5 below.
 *
 * Scaffolding only:
 *  - hal_ipc_node_t / hal_ipc_node_type_t / hal_ipc_processor_t /
 *    processor_type_ipc_* are copied verbatim into common.h;
 *    hal_ipc_processor_desc_t has the real leading fields + len/scratch_buf/
 *    scratch_buf_size with padding for the in/out unions; processor_desc[]
 *    is the table from the get_processor_desc harness.
 *  - socket/bind/setsockopt/listen/accept/recv/send/close/unlink/malloc/free
 *    are redirected to stubs (construct file): fake clients are scripted,
 *    accept() hands them out one by one and then returns -1 so the loop ends.
 *  - MAX_IPC_BUFF is a runner variable so both the single-recv and the
 *    chunked branches can be exercised.
 *  - wifi_hal_error_print / wifi_hal_dbg_print are the REAL macros; the
 *    wifi_hal_print they expand to is the log-sink stub.
 *  - rdk_hal_server_func is static in the original: rdk_hal_server_func_entry()
 *    below only forwards to it so the runner can call it.
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


#define MAX_IPC_BUFF  hipc_max_ipc_buff
#define wifi_hal_dbg_print(format, ...)    wifi_hal_print(WIFI_HAL_LOG_LVL_DEBUG, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)  wifi_hal_print(WIFI_HAL_LOG_LVL_ERROR, format, ##__VA_ARGS__)

#define socket      hsrv_stub_socket
#define bind        hsrv_stub_bind
#define setsockopt  hsrv_stub_setsockopt
#define listen      hsrv_stub_listen
#define accept      hsrv_stub_accept
#define recv        hsrv_stub_recv
#define send        hsrv_stub_send
#define close       hsrv_stub_close
#define unlink      hsrv_stub_unlink
#define malloc      hsrv_stub_malloc
#define free        hsrv_stub_free

/* --- copied verbatim from hal_ipc.c:943 --- */
static void *rdk_hal_server_func(void *arg)
{
    int cli_sock;
    ssize_t nbytes, target_bytes, max_size = MAX_IPC_BUFF;
    socklen_t len;
    struct sockaddr_un cli_sockaddr;
    hal_ipc_processor_desc_t desc;
    hal_ipc_processor_t	serv_processor;
    hal_ipc_node_t *p_ipc_node = (hal_ipc_node_t *)arg;
    unsigned char *tmp;
    unsigned char break_cycle = 0;

    unsigned char *ptr;

    /* FIX 1: (type != A || type != B) is always true, so "== false" never fired and every
     * node type was accepted.  Reject anything that is not a server type. */
    if ((p_ipc_node->type != hal_ipc_node_type_notification_server) &&
            (p_ipc_node->type != hal_ipc_node_type_sync_call_server)) {
        wifi_hal_error_print("%s:%d: Invalid node type: %d\n", __func__, __LINE__, p_ipc_node->type);
        return NULL;
    }

    if ((p_ipc_node->srv_sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        wifi_hal_error_print("%s:%d:server socket create failed err: %d\n", __func__, __LINE__, errno);
        return NULL;
    }

    p_ipc_node->srv_sockaddr.sun_family = AF_UNIX;
    strcpy(p_ipc_node->srv_sockaddr.sun_path, p_ipc_node->node_path);
    len = sizeof(p_ipc_node->srv_sockaddr);

    unlink(p_ipc_node->node_path);
    if (bind(p_ipc_node->srv_sock, (struct sockaddr *)&p_ipc_node->srv_sockaddr, len) == -1) {
        wifi_hal_error_print("%s:%d:server socket bind failed err: %d\n", __func__, __LINE__, errno);
        close(p_ipc_node->srv_sock);
        return NULL;
    }

    if ((setsockopt(p_ipc_node->srv_sock, SOL_SOCKET, SO_RCVBUF, &max_size ,sizeof(int))) < 0) {
        wifi_hal_error_print("%s:%d:server socket size set failed err: %d\n", __func__, __LINE__, errno);
        close(p_ipc_node->srv_sock);
        return NULL;
    }

    if ((setsockopt(p_ipc_node->srv_sock, SOL_SOCKET, SO_SNDBUF, &max_size ,sizeof(int))) < 0) {
        wifi_hal_error_print("%s:%d:server socket size set failed err: %d\n", __func__, __LINE__, errno);
        close(p_ipc_node->srv_sock);
        return NULL;
    }

    if (listen(p_ipc_node->srv_sock, 32) == -1) {
        wifi_hal_error_print("%s:%d:server socket listen failed err: %d\n", __func__, __LINE__, errno);
        close(p_ipc_node->srv_sock);
        return NULL;
    }

    wifi_hal_dbg_print("%s:%d: Enter loop.\n", __func__, __LINE__);

    while ((cli_sock = accept(p_ipc_node->srv_sock, (struct sockaddr *)&cli_sockaddr, &len)) != -1) {
        ///**************************************************************************************///
        ///                 RECEIVE SYNC DATA FROM CLIENT                                        ///
        ///**************************************************************************************///
        break_cycle = 0;
        nbytes = 0;
        target_bytes = 0;
        desc.scratch_buf = NULL;
        desc.scratch_buf_size = 0;
        ptr = (unsigned char *) &desc;
        /* FIX 4: always use the recv loop: a short recv() on the single-recv path left the
         * rest of the descriptor uninitialised stack garbage. */
        if (1) {
            while (target_bytes < sizeof(hal_ipc_processor_desc_t)) {
                if (((nbytes = recv(cli_sock, ptr, (sizeof(hal_ipc_processor_desc_t) - target_bytes > max_size) ? max_size : (sizeof(hal_ipc_processor_desc_t) - target_bytes), 0)) == -1) || (nbytes == 0)) {
                    wifi_hal_error_print("%s:%d:receiving command response failed err: %d data len:%zu\n", __func__, __LINE__, errno, nbytes);
                    close(cli_sock);
                    break_cycle = 1;
                    break;
                }
                ptr += nbytes;
                target_bytes += nbytes;
            }
            if (break_cycle) {
                continue;
            }
        } else {
            if (((nbytes = recv(cli_sock, (unsigned char *) &desc, sizeof(hal_ipc_processor_desc_t), 0)) == -1) || (nbytes == 0)) {
                wifi_hal_error_print("%s:%d:receiving command response failed err: %d data len:%zu\n", __func__, __LINE__, errno, nbytes);
                close(cli_sock);
                continue;
            }
        }

        target_bytes = 0;
        nbytes = 0;

        // check if there is more data to be received
        if (desc.len > sizeof(hal_ipc_processor_desc_t)) {
            /* FIX 5: desc.len / desc.scratch_buf_size come from the client; an inconsistent pair
             * must drop that client, not abort the whole server through assert(). */
            if (desc.scratch_buf_size != (desc.len - sizeof(hal_ipc_processor_desc_t))) {
                wifi_hal_error_print("%s:%d: inconsistent desc.len %u / scratch_buf_size %u\n", __func__, __LINE__, desc.len, desc.scratch_buf_size);
                close(cli_sock);
                continue;
            }
            wifi_hal_dbg_print("%s:%d: Receiving scratch buf of size %d bytes ...\n", __func__, __LINE__, desc.scratch_buf_size);

            // allocate memory for client's data
            // free in serv_proc function
            desc.scratch_buf = malloc(desc.scratch_buf_size);

            if (!desc.scratch_buf) {
                wifi_hal_error_print("%s:%d: failed to allocate memory of %d bytes for scratch buffer\n", __func__, __LINE__, desc.scratch_buf_size);
                close(cli_sock);
                continue;
            }

            memset(desc.scratch_buf, 0, desc.scratch_buf_size);
            tmp = desc.scratch_buf;

            /* FIX 4: always use the loop here too (short recv on the single-recv path). */
            if (1) {
                while (target_bytes < desc.scratch_buf_size) {
                    if (((nbytes = recv(cli_sock, (unsigned char *)tmp, (desc.scratch_buf_size - target_bytes) > max_size ? max_size : (desc.scratch_buf_size - target_bytes), 0)) == -1) || (nbytes == 0)) {
                        wifi_hal_error_print("%s:%d:receiving desc scratch buf in chunks failed err: %d data len:%zu\n", __func__, __LINE__, errno, nbytes);
                        free(desc.scratch_buf);
                        close(cli_sock);
                        break_cycle = 1;
                        break;
                    }
                    /* FIX 2: advance the destination, otherwise every chunk overwrites the start
                     * of the scratch buffer and the rest of it stays zero. */
                    tmp += nbytes;
                    target_bytes += nbytes;
                }
                if (break_cycle) {
                    continue;
                }
                nbytes = target_bytes;
            } else {
                if (((nbytes = recv(cli_sock, (unsigned char *)tmp, desc.scratch_buf_size, 0)) == -1) || (nbytes == 0)) {
                    wifi_hal_error_print("%s:%d:receiving command response failed err: %d data len:%zu\n", __func__, __LINE__, errno, nbytes);
                    free(desc.scratch_buf);
                    close(cli_sock);
                    continue;
                }
            }
        } else {
            // client's data fit into descriptor struct
            desc.scratch_buf = NULL;
            desc.scratch_buf_size = 0;
        }

        wifi_hal_dbg_print("%s:%d: Received command to execute: %s, bytes: %zu, expected: %d\n", __func__, __LINE__, desc.name, sizeof(hal_ipc_processor_desc_t) + nbytes, desc.len);

        /* FIX 5: see above; also release the scratch buffer if one was allocated. */
        if ((sizeof(hal_ipc_processor_desc_t) + nbytes) != desc.len) {
            wifi_hal_error_print("%s:%d: desc.len %u does not match the received %zu bytes\n", __func__, __LINE__, desc.len, sizeof(hal_ipc_processor_desc_t) + nbytes);
            free(desc.scratch_buf);
            close(cli_sock);
            continue;
        }
        ///**************************************************************************************///
        ///                 call the associated descriptor processor                             ///
        ///**************************************************************************************///
        if ((int)desc.type < 0 || desc.type >= hal_ipc_desc_type_max) {
            wifi_hal_error_print("%s:%d: invalid desc.type=%d\n", __func__, __LINE__, desc.type);
            /* FIX 3: no processor will take ownership of the request scratch buffer, free it here. */
            free(desc.scratch_buf);
            desc.scratch_buf = NULL;
            desc.ret = -1;
            desc.len = sizeof(hal_ipc_processor_desc_t);
            desc.scratch_buf_size = 0;
            serv_processor = NULL;
        } else {
            serv_processor = processor_desc[desc.type].ipc_processor[processor_type_ipc_server_output];
        }

        if ((serv_processor != NULL) && (serv_processor(&desc, NULL, NULL, NULL, NULL, NULL) != 0)) {
            wifi_hal_error_print("%s:%d: Execution failed: %s\n", __func__, __LINE__, desc.name);
            // indicate ipc failure
            desc.ret = -1;
            desc.len = sizeof(hal_ipc_processor_desc_t);
            desc.scratch_buf_size = 0;
        }

        ///**************************************************************************************///
        ///                     SEND DATA TO CLIENT                                              ///
        ///**************************************************************************************///

        wifi_hal_dbg_print("%s:%d: Send data to client.\n", __func__, __LINE__);

        // At first send the descriptor structure
        // Next send the descriptor scratch buffer (optional)
        /* FIX 4: always use the send loop (short send() on the single-send path truncated the reply). */
        if (1) {
            nbytes = 0;
            target_bytes = 0;
            ptr = (unsigned char *) &desc;
            while (target_bytes < sizeof(hal_ipc_processor_desc_t)) {
                if ((nbytes = send(cli_sock, ptr, ((sizeof(hal_ipc_processor_desc_t) - target_bytes) > max_size) ? max_size : (sizeof(hal_ipc_processor_desc_t) - target_bytes), 0)) == -1) {
                    wifi_hal_error_print("%s:%d:sending desc in chunks failed err: %d\n", __func__, __LINE__, errno);
                    // serv_processor function depending on descriptor type
                    // might allocate memory for client's response
                    // to desc.scratch_buf pointer and therefore desc.len (data length of descriptor)
                    // will be more than size of desc structure.
                    // if send failed - decide to free memory based on desc data length
                    if (desc.len > sizeof(hal_ipc_processor_desc_t)) {
                        free(desc.scratch_buf);
                    }
                    close(cli_sock);
                    break_cycle = 1;
                    break;
                }
                ptr += nbytes;
                target_bytes += nbytes;
            }
            if (break_cycle) {
                continue;
            }
            nbytes = target_bytes;
        } else if ((nbytes = send(cli_sock, (unsigned char *)&desc, sizeof(hal_ipc_processor_desc_t), 0)) == -1) {
            wifi_hal_error_print("%s:%d:sending desc failed err: %d\n", __func__, __LINE__, errno);
            if (desc.len > sizeof(hal_ipc_processor_desc_t)) {
                free(desc.scratch_buf);
            }
            close(cli_sock);
            continue;
        }

        // now check if there is a data in descriptor scratch buffer
        if (desc.len > sizeof(hal_ipc_processor_desc_t)) {
            nbytes = 0;
            target_bytes = 0;
            tmp = desc.scratch_buf;
            while(target_bytes < desc.scratch_buf_size) {
                if ((nbytes = send(cli_sock, (unsigned char *) tmp, ((desc.scratch_buf_size - target_bytes) > max_size) ? max_size : (desc.scratch_buf_size - target_bytes), 0)) == -1) {
                    wifi_hal_error_print("%s:%d:sending desc in chunks failed err: %d\n", __func__, __LINE__, errno);
                    // condition if (desc.len > sizeof(hal_ipc_processor_desc_t)) means that
                    // we allocated memory in server_proc function
                    free(desc.scratch_buf);
                    close(cli_sock);
                    break_cycle = 1;
                    break;
                }
                tmp += nbytes;
                target_bytes += nbytes;
            }
            if (break_cycle) {
                continue;
            }
            nbytes = target_bytes;

            wifi_hal_dbg_print("%s:%d: Response sent to client for api: %s bytes: %zu\n", __func__, __LINE__, desc.name, sizeof(hal_ipc_processor_desc_t) + nbytes);

            free(desc.scratch_buf);
            close(cli_sock);
        } else {
            wifi_hal_dbg_print("%s:%d: Response sent to client for api: %s bytes: %zu\n", __func__, __LINE__, desc.name, nbytes);
            close(cli_sock);
        }

    } // end of while (accept)

    close(p_ipc_node->srv_sock);

    wifi_hal_dbg_print("%s:%d: Exit.\n", __func__, __LINE__);

    return NULL;
}

/* scaffolding: the original is static */
void *rdk_hal_server_func_entry(void *arg)
{
    return rdk_hal_server_func(arg);
}
