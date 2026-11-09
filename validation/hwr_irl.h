/* hwr_irl.h - plumbing for the intel wifi_setApRetrylimit harness (platform/intel) */
#ifndef HWR_IRL_H
#define HWR_IRL_H
#include "hwr_defs.h"
#define IRL_OUI_LTQ        0xAC9A96u    /* the harness's own values: the vendor header (OUI_LTQ, LTQ_NL80211_VENDOR_SUBCMD_*) is not in the source tree */
#define IRL_SUBCMD_RETRY_LIMIT 0x43u
extern "C" int hwr_int_wifi_setApRetrylimit(void *priv);
typedef struct {
	int calls, last_calls_priv_ok;
	void *last_priv; unsigned last_oui, last_subcmd; unsigned char last_data[16]; unsigned long last_len; int last_nested; void *last_extra;
	int ret;                       /* what the stub wifi_drv_vendor_cmd returns */
} hwr_irl_world_t;
extern hwr_irl_world_t hwr_irl_world;
typedef struct {
	const char *test_name;
	int priv_mode;                 /* 0 NULL, 1 the runner's (poisoned) slab, 2 dangling 0xdeadbeef */
	int vendor_ret;                /* result of the vendor command */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call */
} hwr_irl_case_t;
extern hwr_irl_case_t int_wifi_setApRetrylimit_suite[];
extern "C" void run_all_tests_int_wifi_setApRetrylimit(void);
#endif
