/* hcn_defs.h - harness plumbing for ipc_client_notification_input (self-contained, no common.h) */
#ifndef HCN_DEFS_H
#define HCN_DEFS_H
#include "hso_hal_ipc.h"
#ifdef __cplusplus
extern "C" {
#endif
#define HCN_PAD     256
#define HCN_ARG_SZ  20000                /* >= sizeof(wifi_BTMRequest_t) (17952); runner-owned, tail past arg_len poisoned */
#define HCN_LOG_SZ  256
#define HCN_LOG_USE 128
extern unsigned char hcn_desc_slab[sizeof(hal_ipc_processor_desc_t) + 2 * HCN_PAD];   /* desc at +HCN_PAD, head and tail poisoned */
extern unsigned char hcn_arg_slab[5][HCN_ARG_SZ];
extern size_t        hcn_arg_len[5];
extern char          hcn_log_buf[HCN_LOG_SZ];
extern int           hcn_outstanding;
typedef struct { hal_ipc_processor_desc_t *d; void *a[5]; } hcn_req_t;
typedef struct {
	const char *test_name;
	void (*setup)(hcn_req_t *r);                                  /* builds the descriptor and the argument buffers */
	int  (*verify)(hal_ipc_processor_desc_t *d, int ret);
	int  forked;                                                  /* expected to crash the unfixed function */
	int  exp_ret;
} hcn_case_t;
extern hcn_case_t ipc_client_notification_input_suite[];
int  ipc_client_notification_input_entry(struct hal_ipc_processor_desc *desc, void *a1, void *a2, void *a3, void *a4, void *a5);
void run_all_tests_ipc_client_notification_input(void);
void hcn_free(void *p);
#ifdef __cplusplus
}
#endif
#endif
