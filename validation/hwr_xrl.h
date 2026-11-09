/* hwr_xrl.h - plumbing for the xl_wifi_setApRetrylimit harness (platform/xle) */
#ifndef HWR_XRL_H
#define HWR_XRL_H
#include "hwr_defs.h"
extern "C" int hwr_xl_wifi_setApRetrylimit(void *priv);
typedef struct {
	const char *test_name;
	int in_mode;                 /* 0 NULL, 1 pointer to a fully POISONED runner slab (must not be touched), 2 dangling pointer 0xdeadbeef */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call (the function logs nothing: it must stay as it was) */
	int expected_ret;
} hwr_xrl_case_t;
extern hwr_xrl_case_t xl_wifi_setApRetrylimit_suite[];
extern "C" void run_all_tests_xl_wifi_setApRetrylimit(void);
#endif
