/* hwr_wnw.h - plumbing for the sg_wifi_hal_getNeighboringWiFiStatus harness (src/wifi_hal.c).
 * wifi_radio_info_t / wifi_interface_info_t are minimal STAND-INS with the members the function uses (radio->name; interface->scan_state, scan_has_results and the two scan mutexes);
 * wifi_neighbor_ap2_t is the REAL type.  get_radio_by_rdk_index, get_private_vap_interface and copy_scan_results are stubs over runner data. */
#ifndef HWR_WNW_H
#define HWR_WNW_H
#include "hwr_defs.h"
#include <pthread.h>
#include <stdint.h>
#include <errno.h>
#define HWR_WNW_MAXR 4
#define HWR_WNW_MAXI 4
enum scan_state_type_e { WIFI_SCAN_STATE_NONE, WIFI_SCAN_STATE_ERROR, WIFI_SCAN_STATE_STARTED, WIFI_SCAN_STATE_ABORTED };
#define WIFI_SCAN_RES_COLLECTED_API   0x01
#define WIFI_SCAN_RES_COLLECTED_TEST  0x02
typedef struct wifi_interface_info_t {
	int scan_state;
	pthread_mutex_t scan_state_mutex, scan_info_ap_mutex;
	uint8_t scan_has_results;
	char pad[32];
} wifi_interface_info_t;
typedef struct wifi_radio_info_t { unsigned int index; char name[16]; } wifi_radio_info_t;
typedef struct {
	wifi_radio_info_t radios[HWR_WNW_MAXR];
	wifi_interface_info_t ifs[HWR_WNW_MAXR];
	int no_radio, no_iface, copy_ret;
	int copy_calls, private_calls, mutex_ok_at_copy;
	void *copy_iface;
} hwr_wnw_world_t;
extern hwr_wnw_world_t hwr_wnw_world;
#define HWR_WNW_MARK_SIZE 7u
extern wifi_neighbor_ap2_t hwr_wnw_marker;
extern "C" int hwr_sg_wifi_hal_getNeighboringWiFiStatus(int radioIndex, wifi_neighbor_ap2_t **neighbor_ap_array, unsigned int *output_array_size);
extern "C" int hwr_sg_wifi_hal_getNeighboringWiFiStatus_test(int radioIndex, wifi_neighbor_ap2_t **neighbor_ap_array, unsigned int *output_array_size);
typedef struct {
	const char *test_name;
	int test_api;                  /* 0 wifi_hal_getNeighboringWiFiStatus, 1 wifi_hal_getNeighboringWiFiStatus_test */
	int arr_null, size_null;
	int index;
	int no_radio, no_iface;
	int state;                     /* interface->scan_state */
	unsigned has;                  /* interface->scan_has_results */
	int copy_ret;
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wnw_case_t;
extern hwr_wnw_case_t sg_wifi_hal_getNeighboringWiFiStatus_suite[];
extern "C" void run_all_tests_sg_wifi_hal_getNeighboringWiFiStatus(void);
#endif
