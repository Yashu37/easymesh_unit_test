/* hwr_wgc.h - plumbing for the sg_wifi_setGASConfiguration harness (src/wifi_hal_anqp.c, FEATURE_SUPPORT_PASSPOINT build).
 * wifi_GASConfiguration_t is the REAL HAL type; the static gasCfg[GAS_CFG_TYPE_SUPPORTED] lives in the handler file (exposed by hwr_wgc_cfg()); wifi_applyGASConfiguration is a recording stub. */
#ifndef HWR_WGC_H
#define HWR_WGC_H
#include "hwr_defs.h"
typedef struct { int apply_calls; const wifi_GASConfiguration_t *apply_arg; unsigned char apply_copy[sizeof(wifi_GASConfiguration_t)]; void *unrelated[4]; } hwr_wgc_world_t;
extern hwr_wgc_world_t hwr_wgc_world;
extern "C" wifi_GASConfiguration_t *hwr_wgc_cfg(void);
extern "C" INT hwr_sg_wifi_setGASConfiguration(UINT advertisementID, wifi_GASConfiguration_t *input_struct);
typedef struct {
	const char *test_name;
	unsigned id;                   /* advertisementID */
	int input_null;
	int pattern;                   /* input struct contents: 0 zeros, 1 ones, 2 distinct values, 3 all 0xFF */
	int calls;                     /* 1 or 2 consecutive calls (the second one with the other pattern) */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wgc_case_t;
extern hwr_wgc_case_t sg_wifi_setGASConfiguration_suite[];
extern "C" void run_all_tests_sg_wifi_setGASConfiguration(void);
#endif
