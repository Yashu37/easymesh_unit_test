/* hwr_wnb.h - plumbing for the sg_wifi_hal_set_neighbor_report harness (src/wifi_hal.c).
 * platform_set_neighbor_report_t is declared exactly like wifi_hal_priv.h:777; get_platform_set_neighbor_report_fn (wifi_hal_priv.h:1432) is a runner-controlled getter that can return NULL; the platform
 * function is a recording stub that stores its arguments (the mac pointer only, it never reads the bytes). */
#ifndef HWR_WNB_H
#define HWR_WNB_H
#include "hwr_defs.h"
#include <stdint.h>
typedef int (*platform_set_neighbor_report_t)(uint apIndex, uint add, mac_address_t mac);
typedef struct {
	int no_fn;                     /* get_platform_set_neighbor_report_fn() returns NULL */
	int fn_ret;                    /* what the platform function returns (the wrapper ignores it) */
	int getter_calls, calls;
	uint call_ap, call_add; unsigned char *call_mac;
	void *unrelated[4];            /* poisoned: the wrapper must not touch it */
} hwr_wnb_world_t;
extern hwr_wnb_world_t hwr_wnb_world;
extern "C" void hwr_sg_wifi_hal_set_neighbor_report(uint apIndex, uint add, mac_address_t mac);
typedef struct {
	const char *test_name;
	unsigned ap_index, add;
	int mac_mode;                  /* 0: NULL pointer, 1: runner mac (exact 6-byte heap block), 2: all 0xff, 3: all zero */
	int no_fn;                     /* the getter returns NULL */
	int fn_ret;                    /* platform function return value (ignored by the wrapper) */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wnb_case_t;
extern hwr_wnb_case_t sg_wifi_hal_set_neighbor_report_suite[];
extern "C" void run_all_tests_sg_wifi_hal_set_neighbor_report(void);
#endif
