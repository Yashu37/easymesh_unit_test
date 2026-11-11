/* hwr_wsa.h - plumbing for the sg_wifi_hal_apStatusCode_callback_register harness (src/wifi_hal.c).
 * wifi_device_callbacks_t is a minimal STAND-IN with the members the function uses in their real order (statuscode_cb[MAX_REGISTERED_CB_NUM], num_statuscode_cbs) and the neighbouring other_cb / num_other_cbs;
 * wifi_apStatusCode_callback is the REAL type from the HAL headers.  The table is a stand-alone global so ASan sees a write past statuscode_cb[].  get_hal_device_callbacks (wifi_hal.c:4764) is an accessor
 * over it that can also return NULL. */
#ifndef HWR_WSA_H
#define HWR_WSA_H
#include "hwr_defs.h"
#include <stdint.h>
#define MAX_REGISTERED_CB_NUM 4
#pragma pack(push, 8)
typedef struct {
	void *before[2];
	wifi_apStatusCode_callback statuscode_cb[MAX_REGISTERED_CB_NUM];
	unsigned int num_statuscode_cbs;
	void *other_cb[MAX_REGISTERED_CB_NUM];
	unsigned int num_other_cbs;
} wifi_device_callbacks_t;
#pragma pack(pop)
extern wifi_device_callbacks_t hwr_wsa_table;
extern int hwr_wsa_no_table;
extern "C" void hwr_sg_wifi_hal_apStatusCode_callback_register(wifi_apStatusCode_callback func);
INT hwr_wsa_cb_a(int apIndex, char *src_mac, char *dest_mac, int frame_type, int status);
INT hwr_wsa_cb_b(int apIndex, char *src_mac, char *dest_mac, int frame_type, int status);
typedef struct {
	const char *test_name;
	unsigned start_n;              /* num_statuscode_cbs before the first call (that many slots hold callback A) */
	int calls;                     /* consecutive registrations (alternating B, A, B, ...) */
	int no_table;                  /* get_hal_device_callbacks() returns NULL */
	int null_cb;                   /* the callback passed is NULL (instead of A / B) */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wsa_case_t;
extern hwr_wsa_case_t sg_wifi_hal_apStatusCode_callback_register_suite[];
extern "C" void run_all_tests_sg_wifi_hal_apStatusCode_callback_register(void);
#endif
