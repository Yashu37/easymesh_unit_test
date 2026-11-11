/* hwr_wvs.h - plumbing for the sg_wifi_vapstatus_callback_register harness (src/wifi_hal.c).
 * wifi_device_callbacks_t is a minimal STAND-IN with the members the function uses in their real order (vapstatus_cb[MAX_REGISTERED_CB_NUM], num_vapstatus_cbs) and the neighbouring other_cb / num_other_cbs;
 * wifi_vapstatus_callback is the REAL type from the HAL headers.  The table is a stand-alone global so ASan sees a write past vapstatus_cb[].  get_hal_device_callbacks (wifi_hal.c:4764) is an accessor
 * over it that can also return NULL. */
#ifndef HWR_WVS_H
#define HWR_WVS_H
#include "hwr_defs.h"
#include <stdint.h>
#define MAX_REGISTERED_CB_NUM 4
#pragma pack(push, 8)
typedef struct {
	void *before[2];
	wifi_vapstatus_callback vapstatus_cb[MAX_REGISTERED_CB_NUM];
	unsigned int num_vapstatus_cbs;
	void *other_cb[MAX_REGISTERED_CB_NUM];
	unsigned int num_other_cbs;
} wifi_device_callbacks_t;
#pragma pack(pop)
extern wifi_device_callbacks_t hwr_wvs_table;
extern int hwr_wvs_no_table;
extern "C" INT hwr_sg_wifi_vapstatus_callback_register(wifi_vapstatus_callback func);
INT hwr_wvs_cb_a(INT apIndex, wifi_vapstatus_t status);
INT hwr_wvs_cb_b(INT apIndex, wifi_vapstatus_t status);
typedef struct {
	const char *test_name;
	unsigned start_n;              /* num_vapstatus_cbs before the first call (that many slots hold callback A) */
	int calls;                     /* consecutive registrations (alternating B, A, B, ...) */
	int no_table;                  /* get_hal_device_callbacks() returns NULL */
	int null_cb;                   /* the callback passed is NULL (instead of A / B) */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wvs_case_t;
extern hwr_wvs_case_t sg_wifi_vapstatus_callback_register_suite[];
extern "C" void run_all_tests_sg_wifi_vapstatus_callback_register(void);
#endif
