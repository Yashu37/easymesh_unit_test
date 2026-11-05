/* hwr_rmb.h - types / plumbing for the hal_ipc_RMBeaconReportEvent harness */
#ifndef HWR_RMB_H
#define HWR_RMB_H
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

#define HWR_RMB_SENT_CAP  (sizeof(hal_ipc_processor_desc_t) + 65536)
typedef struct {
	hal_ipc_processor_desc_t *desc;                /* runner-owned descriptor handed out by get_processor_desc */
	hal_ipc_node_t           *node;                /* runner-owned notification client node */
	int node_fail;                                 /* rdk_create_hal_ipc_node returns NULL */
	int fail_at;                                   /* 0 none, 1 socket, 2 bind, 3 setsockopt RCVBUF, 4 setsockopt SNDBUF, 5 connect, 6 send of the descriptor, 7 send of the scratch buffer */
	int sockets, setsockopts, send_calls;
	int live; size_t live_bytes; void *live_ptrs[8];   /* malloc'd - not yet freed (a leak after the call) */
	unsigned char *sent; size_t sent_total;        /* bytes handed to send(): descriptor first, then the scratch buffer */
} hwr_rmb_world_t;
extern hwr_rmb_world_t hwr_rmb_world;
extern hal_ipc_processor_t hwr_rmb_processor_fn;
/* stubs the handler redirects to (construct file) */
extern "C" void *hwr_rmb_malloc(size_t n);
extern "C" void  hwr_rmb_free(void *p);
extern "C" hal_ipc_processor_desc_t *hwr_rmb_get_processor_desc(hal_ipc_desc_type_t type);
extern "C" hal_ipc_node_t *hwr_rmb_create_node(hal_ipc_node_type_t type);
extern "C" int hwr_rmb_socket(int d, int t, int p);
extern "C" int hwr_rmb_bind(int fd, const struct sockaddr *a, socklen_t l);
extern "C" int hwr_rmb_setsockopt(int fd, int lv, int on, const void *v, socklen_t l);
extern "C" int hwr_rmb_connect(int fd, const struct sockaddr *a, socklen_t l);
extern "C" ssize_t hwr_rmb_send(int fd, const void *buf, size_t len, int flags);
extern "C" int hwr_rmb_close(int fd);
extern "C" int hwr_rmb_unlink(const char *p);
extern "C" INT hwr_rmb_call(UINT apIndex, wifi_BeaconReport_t *out_struct, UINT *out_array_size, UCHAR *out_DialogToken);   /* trampoline to the static original */

typedef struct {
	const char *test_name;
	unsigned ap;
	int null_struct, null_size, null_token;     /* out_struct / out_array_size / out_DialogToken passed as NULL */
	unsigned array_size; unsigned token;        /* *out_array_size, *out_DialogToken */
	int fail_at, node_fail;        /* see hwr_rmb_world_t */
	int calls; int check_log;      /* check_log 1: input processor failed, 2: ipc processor failed, 3: node failed, 4: ap_index line */
	int expected_ret;
	int forked;
} hwr_rmb_case_t;
extern hwr_rmb_case_t hal_ipc_RMBeaconReportEvent_suite[];
extern "C" void run_all_tests_hal_ipc_RMBeaconReportEvent(void);
#endif
