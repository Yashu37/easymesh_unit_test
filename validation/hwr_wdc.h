/* hwr_wdc.h - plumbing for the sg_wifi_hal_disconnect harness (src/wifi_hal.c).
 * wifi_interface_info_t is a minimal STAND-IN with the members the function uses (vap_info); the vap info type is the REAL one from wifi_hal.h.  The union u (STA data / hostapd data) is
 * never read by the function.  nl80211_disconnect_sta is a recording stub. */
#ifndef HWR_WDC_H
#define HWR_WDC_H
#include "hwr_defs.h"
#include <stdint.h>
#define HWR_WDC_MAXI 4
typedef struct wifi_interface_info_t {
	wifi_vap_info_t vap_info;
	union { struct { int state; uint8_t pad[60]; } sta; struct { uint8_t blob[64]; } ap; } u;
} wifi_interface_info_t;
typedef struct {
	unsigned int num_ifs;
	wifi_interface_info_t ifs[HWR_WDC_MAXI];
	int disc_calls, disc_ret; wifi_interface_info_t *disc_if;
} hwr_wdc_world_t;
extern hwr_wdc_world_t hwr_wdc_world;
extern "C" int hwr_sg_wifi_hal_disconnect(int ap_index);
typedef struct {
	const char *test_name;
	int vap_index;
	unsigned n_if;                 /* interfaces that exist (vap indexes 0 .. n_if-1) */
	int sta_mask;                  /* bit k: interface k is a STA VAP (the others are AP VAPs) */
	int disc_ret;                  /* result of nl80211_disconnect_sta */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wdc_case_t;
extern hwr_wdc_case_t sg_wifi_hal_disconnect_suite[];
extern "C" void run_all_tests_sg_wifi_hal_disconnect(void);
#endif
