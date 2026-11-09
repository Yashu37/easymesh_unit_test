/* hwr_srl.h - plumbing for the wifi_setApRetrylimit harness (platform/banana-pi) */
#ifndef HWR_SRL_H
#define HWR_SRL_H
#include "hwr_defs.h"
extern "C" int hwr_wifi_setApRetrylimit(void *priv);
typedef struct {
	const char *test_name;
	int priv_mode;                 /* 0 NULL, 1 pointer to a fully POISONED runner slab (must not be touched), 2 dangling pointer 0xdeadbeef */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call (the function logs nothing: it must stay as it was) */
	int expected_ret;
} hwr_srl_case_t;
extern hwr_srl_case_t wifi_setApRetrylimit_suite[];
extern "C" void run_all_tests_wifi_setApRetrylimit(void);
#endif
