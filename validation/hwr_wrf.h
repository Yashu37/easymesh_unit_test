/* hwr_wrf.h - plumbing for the sg_wifi_hal_register_frame_hook harness (src/wifi_hal.c).
 * wifi_device_frame_hooks_t is the REAL layout (src/wifi_hal_priv.h:670-673: num_hooks + frame_hooks_fn[MAX_APPS]); in the library it is the member g_wifi_hal.hooks, here it is a stand-alone global so ASan
 * sees a write past frame_hooks_fn[].  get_device_frame_hooks (wifi_hal.c:4769) is the real accessor over it. */
#ifndef HWR_WRF_H
#define HWR_WRF_H
#include "hwr_defs.h"
#define MAX_APPS 12
#pragma pack(push, 8)   /* the real struct is naturally aligned: frame_hooks_fn[] starts at offset 8 */
typedef struct {
	unsigned int num_hooks;
	wifi_hal_frame_hook_fn_t frame_hooks_fn[MAX_APPS];
} wifi_device_frame_hooks_t;
#pragma pack(pop)
extern wifi_device_frame_hooks_t hwr_wrf_hooks;
extern "C" void hwr_sg_wifi_hal_register_frame_hook(wifi_hal_frame_hook_fn_t func);
INT hwr_wrf_hook_a(INT ap_index, wifi_mgmtFrameType_t type);
INT hwr_wrf_hook_b(INT ap_index, wifi_mgmtFrameType_t type);
typedef struct {
	const char *test_name;
	unsigned start_n;              /* hooks->num_hooks before the first call (that many slots hold hook_a) */
	int calls;                     /* consecutive registrations (alternating hook_b, hook_a, ...) */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wrf_case_t;
extern hwr_wrf_case_t sg_wifi_hal_register_frame_hook_suite[];
extern "C" void run_all_tests_sg_wifi_hal_register_frame_hook(void);
#endif
