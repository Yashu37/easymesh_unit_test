/* hwr_qrl.h - plumbing for the qualcomm wifi_setApRetrylimit harness (platform/qualcomm) */
#ifndef HWR_QRL_H
#define HWR_QRL_H
#include "hwr_defs.h"
/* stand-in for wifi_interface_info_t: only vap_info (the real wifi_vap_info_t) is read, through vap_info.vap_index */
typedef struct { unsigned char pre[24]; wifi_vap_info_t vap_info; unsigned char post[24]; } qrl_iface_t;
extern "C" int hwr_qc_wifi_setApRetrylimit(void *priv);
typedef struct { int calls; int last_ap; unsigned last_limit; int ret; } hwr_qrl_world_t;   /* wifi_setApRetryLimit stub: calls, last arguments, result */
extern hwr_qrl_world_t hwr_qrl_world;
typedef struct {
	const char *test_name;
	int priv_mode;                 /* 0 NULL, 1 the runner's interface object (all but vap_index POISONED during the call) */
	unsigned vap_index;
	int limit_ret;                 /* result of the stubbed wifi_setApRetryLimit */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call */
} hwr_qrl_case_t;
extern hwr_qrl_case_t qc_wifi_setApRetrylimit_suite[];
extern "C" void run_all_tests_qc_wifi_setApRetrylimit(void);
#endif
