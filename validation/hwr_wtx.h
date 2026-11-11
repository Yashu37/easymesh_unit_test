/* hwr_wtx.h - plumbing for the sg_wifi_8021x_data_tx_callback_register harness (src/wifi_hal_data_rx.c).
 * wifi_device_callbacks_t is a minimal STAND-IN with the member the function writes (eapol_frame_tx_callback) between neighbouring members (the rx callback slot next to it must stay untouched);
 * wifi_sent8021xFrame_callback / wifi_received8021xFrame_callback are the REAL HAL types.  get_device_callbacks (wifi_hal_rdk_util.c:68) returns the address of a global table and never NULL, so the
 * accessor here does the same over runner data. */
#ifndef HWR_WTX_H
#define HWR_WTX_H
#include "hwr_defs.h"
typedef struct {
	void *before[2];
	wifi_received8021xFrame_callback eapol_frame_rx_callback;
	wifi_sent8021xFrame_callback eapol_frame_tx_callback;
	void *after[2];
} wifi_device_callbacks_t;
typedef struct { wifi_device_callbacks_t cbs; int accessor_calls; } hwr_wtx_world_t;
extern hwr_wtx_world_t hwr_wtx_world;
extern "C" void hwr_sg_wifi_8021x_data_tx_callback_register(wifi_sent8021xFrame_callback func);
void hwr_wtx_tx_a(unsigned int ap_index, mac_address_t sta, wifi_eapol_type_t type, void *data, unsigned int len);
void hwr_wtx_tx_b(unsigned int ap_index, mac_address_t sta, wifi_eapol_type_t type, void *data, unsigned int len);
void hwr_wtx_rx_a(unsigned int ap_index, mac_address_t sta, wifi_eapol_type_t type, void *data, unsigned int len);
typedef struct {
	const char *test_name;
	int old_tx;                    /* tx callback registered before: 0 none, 1 callback A, 2 callback B */
	int old_rx;                    /* rx callback registered before: 0 none, 1 rx callback */
	int new_cb;                    /* callback passed: 0 NULL, 1 A, 2 B */
	int calls;                     /* number of consecutive registrations (the second one passes the other callback) */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wtx_case_t;
extern hwr_wtx_case_t sg_wifi_8021x_data_tx_callback_register_suite[];
extern "C" void run_all_tests_sg_wifi_8021x_data_tx_callback_register(void);
#endif
