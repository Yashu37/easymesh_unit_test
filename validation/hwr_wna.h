/* hwr_wna.h - plumbing for the sg_wifi_hal_newApAssociatedDevice_callback_register harness (src/wifi_hal.c).
 * wifi_device_callbacks_t is a minimal STAND-IN with the members the function uses in their real order (assoc_cb[MAX_REGISTERED_CB_NUM], num_assoc_cbs) and the neighbouring disassoc_cb / num_disassoc_cbs;
 * wifi_newApAssociatedDevice_callback is the REAL type from the HAL headers.  The table is a stand-alone global so ASan sees a write past assoc_cb[].  get_hal_device_callbacks (wifi_hal.c:4764) is an accessor
 * over it that can also return NULL. */
#ifndef HWR_WNA_H
#define HWR_WNA_H
#include "hwr_defs.h"
#include <stdint.h>
#define MAX_REGISTERED_CB_NUM 4
#pragma pack(push, 8)
typedef struct {
	void *before[2];
	wifi_newApAssociatedDevice_callback assoc_cb[MAX_REGISTERED_CB_NUM];
	unsigned int num_assoc_cbs;
	void *disassoc_cb[MAX_REGISTERED_CB_NUM];
	unsigned int num_disassoc_cbs;
} wifi_device_callbacks_t;
#pragma pack(pop)
extern wifi_device_callbacks_t hwr_wna_table;
extern int hwr_wna_no_table;
extern "C" void hwr_sg_wifi_hal_newApAssociatedDevice_callback_register(wifi_newApAssociatedDevice_callback func);
INT hwr_wna_cb_a(INT ap_index, wifi_associated_dev_t *assoc_dev);
INT hwr_wna_cb_b(INT ap_index, wifi_associated_dev_t *assoc_dev);
typedef struct {
	const char *test_name;
	unsigned start_n;              /* num_assoc_cbs before the first call (that many slots hold callback A) */
	int calls;                     /* consecutive registrations (alternating B, A, B, ...) */
	int no_table;                  /* get_hal_device_callbacks() returns NULL */
	int null_cb;                   /* the callback passed is NULL (instead of A / B) */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wna_case_t;
extern hwr_wna_case_t sg_wifi_hal_newApAssociatedDevice_callback_register_suite[];
extern "C" void run_all_tests_sg_wifi_hal_newApAssociatedDevice_callback_register(void);
#endif
