/* hwr_gcl.h - plumbing for the wifi_getApAssociatedClientDiagnosticResult harness (platform/banana-pi) */
#ifndef HWR_GCL_H
#define HWR_GCL_H
#include "hwr_defs.h"
extern "C" INT hwr_wifi_getApAssociatedClientDiagnosticResult(INT ap_index, char *key, wifi_associated_dev3_t *assoc);
typedef struct {
	const char *test_name;
	int ap_index;
	int key_mode;                  /* 0 NULL, 1 pointer to a fully POISONED runner slab (must not be touched), 2 dangling pointer 0xdeadbeef */
	int assoc_mode;                /* same encoding for the wifi_associated_dev3_t pointer */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call (the function logs nothing: it must stay as it was) */
	int expected_ret;
} hwr_gcl_case_t;
extern hwr_gcl_case_t wifi_getApAssociatedClientDiagnosticResult_suite[];
extern "C" void run_all_tests_wifi_getApAssociatedClientDiagnosticResult(void);
#endif
