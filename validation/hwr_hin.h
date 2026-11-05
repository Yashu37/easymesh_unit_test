/* hwr_hin.h - types / plumbing for the hal_ipc_init harness */
#ifndef HWR_HIN_H
#define HWR_HIN_H
#include "hwr_defs.h"
#define HWR_HIN_MAX_AP 15                                      /* MAX_AP_INDEX of the non VAP_REINDEX build */
typedef struct { wifi_BTMQueryRequest_callback query_callback; wifi_BTMResponse_callback response_callback; } wifi_BTM_callbacks_t;   /* verbatim from wifi_hal_rdk_framework.h */
typedef struct {                                               /* the members of wifi_device_callbacks_t the registration functions touch */
	wifi_steering_eventCB_t steering_event_callback;
	wifi_RMBeaconReport_callback bcnrpt_callback[HWR_HIN_MAX_AP];
	wifi_BTM_callbacks_t btm_callback[HWR_HIN_MAX_AP];
} wifi_device_callbacks_t;
typedef struct { wifi_device_callbacks_t device_callbacks; } hwr_hin_world_t;
extern hwr_hin_world_t *hwr_hin_world;                         /* runner-owned slab */

/* hal_ipc_node_type_t comes from hso_hal_ipc.h (verbatim from hal_ipc.h) */
typedef struct { char node_path[64]; hal_ipc_node_type_t type; } hal_ipc_node_t;     /* trimmed: the function only checks the pointer */
extern "C" hal_ipc_node_t *hwr_hin_create_node(hal_ipc_node_type_t type);
extern "C" int hwr_hal_ipc_init(void);                         /* renamed, see the handler file */
extern "C" void *hwr_hin_cb_steer(void);
extern "C" void *hwr_hin_cb_rm(void);
extern "C" void *hwr_hin_cb_btmq(void);
extern "C" void *hwr_hin_cb_btmr(void);

typedef struct {
	int calls[hal_ipc_node_type_max];                          /* rdk_create_hal_ipc_node calls per node type */
	int fail_mask;                                             /* bit n: creating node type n returns NULL */
} hwr_hin_rec_t;
extern hwr_hin_rec_t hwr_hin_rec;
extern hal_ipc_node_t hwr_hin_nodes[hal_ipc_node_type_max];

typedef struct {
	const char *test_name;
	unsigned foreign_rm;           /* bitmask of AP indexes whose beacon callback is already taken by another registrant */
	int foreign_steer, foreign_btm;/* steering / BTM callbacks already set by another registrant */
	int node_fail;                 /* bit 0: notification client creation fails, bit 1: sync call server creation fails */
	int init_calls;                /* how many times hal_ipc_init() is called in a row */
	int expected_ret[3];           /* return value of each call */
	int clients, servers;          /* total rdk_create_hal_ipc_node calls per type over all calls; -1 = not checked */
	int check_log;                 /* 1: RM beacon registration failure line, 2: client node line, 3: server node line */
} hwr_hin_case_t;
extern hwr_hin_case_t hal_ipc_init_suite[];
extern "C" void run_all_tests_hal_ipc_init(void);
#endif
