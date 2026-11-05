/* hwr_sse.h - types / plumbing for the hal_ipc_send_steering_event harness */
#ifndef HWR_SSE_H
#define HWR_SSE_H
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

#define HWR_SSE_SENT_CAP  (sizeof(hal_ipc_processor_desc_t) + 4096)
typedef struct {
	hal_ipc_processor_desc_t *desc;                /* runner-owned descriptor handed out by get_processor_desc */
	hal_ipc_node_t           *node;                /* runner-owned notification client node */
	int node_fail;                                 /* rdk_create_hal_ipc_node returns NULL */
	int fail_at;                                   /* 0 none, 1 socket, 2 bind, 3 setsockopt RCVBUF, 4 setsockopt SNDBUF, 5 connect, 6 send of the descriptor */
	int sockets, setsockopts, send_calls;
	int live; size_t live_bytes; void *live_ptrs[8];   /* malloc'd - not yet freed (a leak after the call) */
	unsigned char *sent; size_t sent_total;        /* bytes handed to send(): descriptor first, then the scratch buffer */
} hwr_sse_world_t;
extern hwr_sse_world_t hwr_sse_world;
extern hal_ipc_processor_t hwr_sse_processor_fn;
/* stubs the handler redirects to (construct file) */
extern "C" void *hwr_sse_malloc(size_t n);
extern "C" void  hwr_sse_free(void *p);
extern "C" hal_ipc_processor_desc_t *hwr_sse_get_processor_desc(hal_ipc_desc_type_t type);
extern "C" hal_ipc_node_t *hwr_sse_create_node(hal_ipc_node_type_t type);
extern "C" int hwr_sse_socket(int d, int t, int p);
extern "C" int hwr_sse_bind(int fd, const struct sockaddr *a, socklen_t l);
extern "C" int hwr_sse_setsockopt(int fd, int lv, int on, const void *v, socklen_t l);
extern "C" int hwr_sse_connect(int fd, const struct sockaddr *a, socklen_t l);
extern "C" ssize_t hwr_sse_send(int fd, const void *buf, size_t len, int flags);
extern "C" int hwr_sse_close(int fd);
extern "C" int hwr_sse_unlink(const char *p);
extern "C" void hwr_sse_call(UINT steeringgroupIndex, wifi_steering_event_t *event);   /* trampoline to the static original */

typedef struct {
	const char *test_name;
	unsigned group;
	int null_event;                 /* event passed as NULL */
	int ev_type; int ev_ap; unsigned long long ev_ts;   /* fields set in the event; the rest of it is a byte pattern */
	int fail_at, node_fail;         /* see hwr_sse_world_t */
	int calls; int check_log;       /* check_log 1: input processor failed, 2: ipc processor failed, 3: node failed, 4: steering event line */
	int expected_ret;               /* 0 = the event is sent, -1 = it is not */
} hwr_sse_case_t;
extern hwr_sse_case_t hal_ipc_send_steering_event_suite[];
extern "C" void run_all_tests_hal_ipc_send_steering_event(void);
#endif
