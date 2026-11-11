/* hwr_wcn.h - plumbing for the sg_wifi_hal_configNeighborReports harness (src/wifi_hal.c).
 * wifi_interface_info_t / struct hostapd_bss_config are minimal STAND-INS with the members the function uses (interface->vap_info, interface->u.ap.conf, interface->wnm_bss_trans_query_auto_resp;
 * conf->bss_transition, conf->radio_measurements[]); wifi_vap_info_t (u.bss_info.nbrReportActivated / bssTransitionActivated) is the REAL type.  get_interface_by_vap_index is a stub over runner data. */
#ifndef HWR_WCN_H
#define HWR_WCN_H
#include "hwr_defs.h"
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>
#define HWR_WCN_MAXI 4
#define WLAN_RRM_CAPS_NEIGHBOR_REPORT 0x02
typedef uint8_t u8;
struct hostapd_bss_config { int before; int bss_transition; u8 radio_measurements[5]; int after; };
typedef struct wifi_interface_info_t {
	wifi_vap_info_t vap_info;
	union { struct { struct hostapd_bss_config conf; } ap; struct { int state; } sta; } u;
	int wnm_bss_trans_query_auto_resp;
	char pad[16];
} wifi_interface_info_t;
typedef struct { pthread_mutex_t hapd_lock; } hwr_wcn_hal_t;
typedef struct { hwr_wcn_hal_t hal; wifi_interface_info_t ifs[HWR_WCN_MAXI]; } hwr_wcn_world_t;
extern hwr_wcn_world_t hwr_wcn_world;
extern "C" int hwr_sg_wifi_hal_configNeighborReports(UINT apIndex, bool enable, bool auto_resp);
typedef struct {
	const char *test_name;
	unsigned apIndex;
	int vap_sta;                   /* the interface is in STA mode */
	int enable, auto_resp;
	unsigned rm0;                  /* conf->radio_measurements[0] before the call */
	int old_enable, old_auto;      /* previous activation / auto-response state */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wcn_case_t;
extern hwr_wcn_case_t sg_wifi_hal_configNeighborReports_suite[];
extern "C" void run_all_tests_sg_wifi_hal_configNeighborReports(void);
#endif
