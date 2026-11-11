/* hwr_wgr.h - plumbing for the sg_wifi_hal_get_RegDomain harness (src/wifi_hal.c).
 * platform_get_RegDomain_t is declared exactly like wifi_hal_priv.h:781; wifi_radio_index_t is the REAL type from the HAL headers.  get_platform_get_RegDomain_fn (wifi_hal_nl80211_utils.c:4635) is a
 * runner-controlled getter that can return NULL (in the real tree no platform sets it, so it is NULL there); the platform function is a recording stub that returns a runner-chosen value and writes a
 * runner-chosen domain when asked and when the pointer is non-NULL. */
#ifndef HWR_WGR_H
#define HWR_WGR_H
#include "hwr_defs.h"
#include <stdint.h>
typedef int (*platform_get_RegDomain_t)(wifi_radio_index_t index, uint *reg_domain);
typedef struct {
	int no_fn, fn_ret, write_dom; unsigned dom_value;
	int getter_calls, calls; unsigned call_index; uint *call_out;
	void *unrelated[4];            /* poisoned: the wrapper must not touch it */
} hwr_wgr_world_t;
extern hwr_wgr_world_t hwr_wgr_world;
extern "C" INT hwr_sg_wifi_hal_get_RegDomain(wifi_radio_index_t radioIndex, UINT *reg_domain);
typedef struct {
	const char *test_name;
	unsigned radio_index;
	int out_null;                  /* reg_domain is NULL */
	int no_fn;                     /* the getter returns NULL */
	int fn_ret;                    /* platform function return value */
	int write_dom; unsigned dom_value;     /* platform writes dom_value to the output when write_dom */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wgr_case_t;
extern hwr_wgr_case_t sg_wifi_hal_get_RegDomain_suite[];
extern "C" void run_all_tests_sg_wifi_hal_get_RegDomain(void);
#endif
