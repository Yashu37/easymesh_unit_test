/* hwr_gsd.h - types / plumbing for the wifi_hal_steering_clientDisconnect harness */
#ifndef HWR_GSD_H
#define HWR_GSD_H
#include "hwr_defs.h"
#include <pthread.h>
#include <stdint.h>
struct hwr_gsd_conf { char iface[16]; };
struct hwr_gsd_hostapd { hwr_gsd_conf *conf; };
typedef struct { hwr_gsd_hostapd hapd; char pad[256]; } hwr_gsd_ap_t;               /* wifi_ap_priv_t: hapd first */
typedef struct { char junk[sizeof(hwr_gsd_ap_t)]; } hwr_gsd_sta_t;                  /* wifi_sta_priv_t: other state in the same bytes */
typedef struct { int vap_index; wifi_vap_info_t vap_info; union { hwr_gsd_ap_t ap; hwr_gsd_sta_t sta; } u; } hwr_gsd_if_t;
#define wifi_interface_info_t hwr_gsd_if_t
typedef struct { pthread_mutex_t hapd_lock; } hwr_gsd_world_t;
extern hwr_gsd_world_t hwr_gsd_world;
extern "C" hwr_gsd_if_t *hwr_gsd_get_interface(unsigned int vap_index);
extern "C" void hwr_gsd_ap_sta_disconnect(hwr_gsd_hostapd *hapd, void *sta, const unsigned char *addr, uint16_t reason);
extern "C" INT hwr_wifi_hal_steering_clientDisconnect(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac, wifi_disconnectType_t type, UINT reason);   /* renamed, see the handler file */

typedef struct {
	const char *test_name;
	unsigned group; int ap; unsigned char mac[6];
	unsigned null_mask;            /* 1: client_mac passed as NULL */
	int type;                      /* wifi_disconnectType_t value */
	unsigned reason;
	int sta_mode;                  /* the interface is a STA VAP (u holds STA state, no hostapd) */
	int calls; int check_log;
	int expected_ret;
	int expect_call;               /* ap_sta_disconnect called */
	int forked;
} hwr_gsd_case_t;
extern hwr_gsd_case_t wifi_hal_steering_clientDisconnect_suite[];
extern "C" void run_all_tests_wifi_hal_steering_clientDisconnect(void);
typedef struct { int calls; hwr_gsd_hostapd *hapd; void *sta; int addr_null; unsigned char addr[6]; uint16_t reason; int locked_in_call; } hwr_gsd_rec_t;
extern hwr_gsd_rec_t hwr_gsd_rec;
void hwr_gsd_configure(hwr_gsd_if_t *iface);
#endif
