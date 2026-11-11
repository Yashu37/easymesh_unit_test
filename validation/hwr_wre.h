/* hwr_wre.h - plumbing for the sg_wifi_hal_radius_eap_failure_callback_register harness (src/wifi_hal.c).
 * wifi_device_callbacks_t is a minimal STAND-IN with the members the function uses in their real order (radius_eap_cb[MAX_REGISTERED_CB_NUM], num_radius_eap_cbs) and the neighbouring other_cb / num_other_cbs;
 * wifi_radiusEapFailure_callback is the REAL type from the HAL headers.  The table is a stand-alone global so ASan sees a write past radius_eap_cb[].  get_hal_device_callbacks (wifi_hal.c:4764) is an accessor
 * over it that can also return NULL. */
#ifndef HWR_WRE_H
#define HWR_WRE_H
#include "hwr_defs.h"
#include <stdint.h>
#define MAX_REGISTERED_CB_NUM 4
#pragma pack(push, 8)
typedef struct {
	void *before[2];
	wifi_radiusEapFailure_callback radius_eap_cb[MAX_REGISTERED_CB_NUM];
	unsigned int num_radius_eap_cbs;
	void *other_cb[MAX_REGISTERED_CB_NUM];
	unsigned int num_other_cbs;
} wifi_device_callbacks_t;
#pragma pack(pop)
extern wifi_device_callbacks_t hwr_wre_table;
extern int hwr_wre_no_table;
extern "C" void hwr_sg_wifi_hal_radius_eap_failure_callback_register(wifi_radiusEapFailure_callback func);
INT hwr_wre_cb_a(INT apIndex, mac_address_t sta_mac, INT failure_reason);
INT hwr_wre_cb_b(INT apIndex, mac_address_t sta_mac, INT failure_reason);
typedef struct {
	const char *test_name;
	unsigned start_n;              /* num_radius_eap_cbs before the first call (that many slots hold callback A) */
	int calls;                     /* consecutive registrations (alternating B, A, B, ...) */
	int no_table;                  /* get_hal_device_callbacks() returns NULL */
	int null_cb;                   /* the callback passed is NULL (instead of A / B) */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wre_case_t;
extern hwr_wre_case_t sg_wifi_hal_radius_eap_failure_callback_register_suite[];
extern "C" void run_all_tests_sg_wifi_hal_radius_eap_failure_callback_register(void);
#endif
