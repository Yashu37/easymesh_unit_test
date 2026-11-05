/* hwr_bqe.h - types / plumbing for the hal_ipc_BTMQueryRequestEvent harness */
#ifndef HWR_BQE_H
#define HWR_BQE_H
#include "hwr_defs.h"
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>

typedef struct {                                   /* copied verbatim from hal_ipc.h */
    char                node_path[64];
    pthread_t           listener_tid;
    int                 srv_sock;
    struct sockaddr_un  srv_sockaddr;
    hal_ipc_node_type_t type;
} hal_ipc_node_t;

#define HWR_BQE_SENT_CAP  (sizeof(hal_ipc_processor_desc_t) + 65536)
typedef struct {
	hal_ipc_processor_desc_t *desc;                /* runner-owned descriptor handed out by get_processor_desc */
	hal_ipc_node_t           *node;                /* runner-owned notification client node */
	int node_fail;                                 /* rdk_create_hal_ipc_node returns NULL */
	int fail_at;                                   /* 0 none, 1 socket, 2 bind, 3 setsockopt RCVBUF, 4 setsockopt SNDBUF, 5 connect, 6 send of the descriptor, 7 send of the scratch buffer */
	int sockets, setsockopts, send_calls;
	int live; size_t live_bytes; void *live_ptrs[8];   /* malloc'd - not yet freed (a leak after the call) */
	unsigned char *sent; size_t sent_total;        /* bytes handed to send(): descriptor first, then the scratch buffer */
} hwr_bqe_world_t;
extern hwr_bqe_world_t hwr_bqe_world;
extern hal_ipc_processor_t hwr_bqe_processor_fn;
/* stubs the handler redirects to (construct file) */
extern "C" void *hwr_bqe_malloc(size_t n);
extern "C" void  hwr_bqe_free(void *p);
extern "C" hal_ipc_processor_desc_t *hwr_bqe_get_processor_desc(hal_ipc_desc_type_t type);
extern "C" hal_ipc_node_t *hwr_bqe_create_node(hal_ipc_node_type_t type);
extern "C" int hwr_bqe_socket(int d, int t, int p);
extern "C" int hwr_bqe_bind(int fd, const struct sockaddr *a, socklen_t l);
extern "C" int hwr_bqe_setsockopt(int fd, int lv, int on, const void *v, socklen_t l);
extern "C" int hwr_bqe_connect(int fd, const struct sockaddr *a, socklen_t l);
extern "C" ssize_t hwr_bqe_send(int fd, const void *buf, size_t len, int flags);
extern "C" int hwr_bqe_close(int fd);
extern "C" int hwr_bqe_unlink(const char *p);
extern "C" INT hwr_bqe_call(UINT apIndex, CHAR *peerMac, wifi_BTMQuery_t *query, UINT inMemSize, wifi_BTMRequest_t *request);   /* trampoline to the static original */

typedef struct {
	const char *test_name;
	unsigned ap;
	const char *mac;               /* peerMac string, NULL = NULL pointer */
	int null_query, null_request;
	unsigned in_mem_size;
	int fail_at, node_fail;        /* see hwr_bqe_world_t */
	int calls; int check_log;      /* check_log 1: input processor failed, 2: ipc processor failed, 3: node failed, 4: ap_index line */
	int expected_ret;
	const char *exp_mac;           /* 12 hex digits the descriptor must carry, NULL = not compared */
	int forked;
} hwr_bqe_case_t;
extern hwr_bqe_case_t hal_ipc_BTMQueryRequestEvent_suite[];
extern "C" void run_all_tests_hal_ipc_BTMQueryRequestEvent(void);
#endif
