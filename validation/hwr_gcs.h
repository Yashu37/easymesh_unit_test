/* hwr_gcs.h - types / plumbing for the wifi_hal_steering_clientSet harness */
#ifndef HWR_GCS_H
#define HWR_GCS_H
#include "hwr_defs.h"
#include <pthread.h>
#include <stdint.h>
#include <time.h>
#define SSID_MAX_LEN 32
#define BM_STA_TYPE_CLIENT_SET 0x02
typedef struct { int vap_index; } hwr_gcs_interface_t;
#define wifi_interface_info_t hwr_gcs_interface_t
typedef enum { ACTIVE = 1, INACTIVE, MAX_STATE } hwr_gcs_client_state_t;
#define client_state_t hwr_gcs_client_state_t
/* bm_sta_list_t: layout of wifi_hal_priv.h:889-907 */
typedef struct {
    mac_address_t mac_addr; time_t assoc_time; time_t disassoc_time; time_t active; uint8_t vap_index; char ssid[SSID_MAX_LEN];
    uint8_t inactive_state; int32_t rssi; int32_t rssi_changed; int32_t rssi_change_auth; int32_t rssi_change_assoc;
    uint8_t type; uint8_t is_acl_set; client_state_t state; uint32_t event_sent; unsigned long int rx_tot_pkts; unsigned long int tx_tot_pkts;
    wifi_steering_clientConfig_t bm_client_cfg;
} hwr_bm_sta_list_t;
#define bm_sta_list_t hwr_bm_sta_list_t
typedef struct { pthread_mutex_t steering_data_lock; } hwr_gcs_world_t;
extern hwr_gcs_world_t hwr_gcs_world;
/* stubs (construct file) */
extern "C" hwr_gcs_interface_t *hwr_gcs_get_interface(unsigned int vap_index);
extern "C" hwr_bm_sta_list_t *hwr_gcs_add_stalist(hwr_gcs_interface_t *interface, char *ssid, mac_address_t client_mac, uint8_t type);
extern "C" int hwr_gcs_del_mac_list(uint32_t vap_index, hwr_bm_sta_list_t *sta_info);
extern "C" INT hwr_wifi_hal_steering_clientSet(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac, wifi_steering_clientConfig_t *config);   /* renamed, see the handler file */

typedef struct {
	const char *test_name;
	unsigned group; int ap; unsigned char mac[6];
	unsigned cfg[8];               /* probeHWM, probeLWM, authHWM, authLWM, inactXing, highXing, lowXing, rejectReason */
	unsigned null_mask;            /* 1 client_mac, 2 config passed as NULL */
	int add_fail;                  /* steering_add_stalist returns NULL */
	int del_ret;                   /* wifi_steering_del_mac_list result */
	int calls; int check_log;
	int expected_ret;
	int expect_add;                /* expected steering_add_stalist calls (per call) */
	int expect_del;                /* expected wifi_steering_del_mac_list calls (per call) */
	int forked;                    /* crashes the unfixed function: run in a child */
} hwr_gcs_case_t;
extern hwr_gcs_case_t wifi_hal_steering_clientSet_suite[];
extern "C" void run_all_tests_wifi_hal_steering_clientSet(void);
typedef struct { int add_calls; int del_calls; hwr_gcs_interface_t *add_if; void *add_ssid; unsigned char add_mac[6]; int add_type; uint32_t del_vap; hwr_bm_sta_list_t *del_sta; } hwr_gcs_rec_t;
extern hwr_gcs_rec_t hwr_gcs_rec;
void hwr_gcs_configure(hwr_bm_sta_list_t *sta, int add_fail, int del_ret);
#endif
