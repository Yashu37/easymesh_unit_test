/* hwr_wsd.h - plumbing for the sg_wifi_hal_sm_deinit harness (src/wifi_hal.c).
 * wifi_interface_info_t / struct wpa_sm / struct eapol_sm are minimal STAND-INS with the members the function uses (interface->vap_info, interface->u.sta.wpa_sm, wpa_sm->eapol); the vap
 * info type is the REAL one from wifi_hal.h.  The union u overlaps the STA data with an AP blob exactly as the real wifi_interface_info_t does.  eapol_sm_deinit / wpa_sm_deinit free the
 * runner-allocated objects (so ASan sees a double free or a leak) and record the call. */
#ifndef HWR_WSD_H
#define HWR_WSD_H
#include "hwr_defs.h"
#include <pthread.h>
#include <stdint.h>
#define HWR_WSD_MAXI 4
struct eapol_sm { int state; };
struct wpa_sm { struct eapol_sm *eapol; int pad[6]; };
typedef struct wifi_interface_info_t {
	wifi_vap_info_t vap_info;
	union {
		struct { struct wpa_sm *wpa_sm; int pad[4]; } sta;
		struct { uint8_t blob[64]; } ap;            /* the AP side of the union: hostapd data, not a wpa_sm pointer */
	} u;
} wifi_interface_info_t;
typedef struct {
	unsigned int num_ifs;
	wifi_interface_info_t ifs[HWR_WSD_MAXI];
	int eapol_calls, sm_calls; struct eapol_sm *eapol_arg; struct wpa_sm *sm_arg; struct wpa_sm *sm_eapol_at_call;
} hwr_wsd_world_t;
extern hwr_wsd_world_t hwr_wsd_world;
extern "C" int hwr_sg_wifi_hal_sm_deinit(int vap_index);
typedef struct {
	const char *test_name;
	int vap_index;
	unsigned n_if;                 /* interfaces that exist (vap indexes 0 .. n_if-1) */
	int sta_mask;                  /* bit k: interface k is a STA VAP (the others are AP VAPs) */
	int sm_mask;                   /* bit k: STA interface k has a wpa_sm */
	int no_eapol;                  /* the wpa_sm of the STA VAPs has eapol == NULL */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wsd_case_t;
extern hwr_wsd_case_t sg_wifi_hal_sm_deinit_suite[];
extern "C" void run_all_tests_sg_wifi_hal_sm_deinit(void);
#endif
