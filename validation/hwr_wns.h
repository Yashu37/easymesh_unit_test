/* hwr_wns.h - plumbing for the sg_wifi_getNASta harness (src/wifi_hal.c).
 * wifi_na_sta_req_params_t / wifi_na_sta_info_t are the REAL types from wifi_hal_telemetry.h.  The function has two builds: with MXL_WIFI it checks its arguments and forwards to platform_get_nasta
 * (wifi_hal_priv.h:1561, implemented in platform/intel/platform.c:175), without MXL_WIFI it returns WIFI_HAL_ERROR; this harness compiles the MXL_WIFI build (the one with logic).  platform_get_nasta is a
 * recording stub that returns a runner-chosen value and fills sta_info when asked. */
#ifndef HWR_WNS_H
#define HWR_WNS_H
#include "hwr_defs.h"
#include <stdint.h>
typedef struct {
	int fn_ret, write_info;
	int calls; int call_ap; const wifi_na_sta_req_params_t *call_params; wifi_na_sta_info_t *call_info;
	void *unrelated[4];            /* poisoned: the wrapper must not touch it */
} hwr_wns_world_t;
extern hwr_wns_world_t hwr_wns_world;
extern "C" INT hwr_sg_wifi_getNASta(INT apIndex, const wifi_na_sta_req_params_t *params, wifi_na_sta_info_t *sta_info);
typedef struct {
	const char *test_name;
	int ap_index;                  /* apIndex argument (valid: 0 .. MAX_VAP-1) */
	int params_null, info_null;
	int fn_ret;                    /* platform_get_nasta result */
	int write_info;                /* the platform fills sta_info (rcpi 120) */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wns_case_t;
extern hwr_wns_case_t sg_wifi_getNASta_suite[];
extern "C" void run_all_tests_sg_wifi_getNASta(void);
#endif
