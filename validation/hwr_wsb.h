/* hwr_wsb.h - plumbing for the sg_wifi_hal_add_station_bridge harness (src/wifi_hal.c).
 * nl80211_remove_from_bridge (wifi_hal_nl80211.c:4319) and nl80211_create_bridge (wifi_hal_nl80211.c:4376) are recording stubs.  Like the real ones they DEREFERENCE their name arguments unconditionally
 * (strlen on every name: the real code feeds them to rtnl_link_get_by_name / strcmp / ovs_if_get_br), so a NULL name crashes inside the stub exactly where it crashes in the real callee. */
#ifndef HWR_WSB_H
#define HWR_WSB_H
#include "hwr_defs.h"
#include <stdint.h>
typedef struct {
	int rm_calls, cr_calls, order;                 /* order: sequence number of the next call */
	int rm_order, cr_order;
	const char *rm_name, *cr_if, *cr_br;
	int rm_ret, cr_ret;
	size_t seen_len;                               /* keeps the strlen result alive */
	void *unrelated[4];                            /* poisoned: the wrapper must not touch it */
} hwr_wsb_world_t;
extern hwr_wsb_world_t hwr_wsb_world;
extern "C" int hwr_sg_wifi_hal_add_station_bridge(char *interface_name, char *bridge_name);
typedef struct {
	const char *test_name;
	int if_mode;                   /* 0: NULL, 1: "wlan0", 2: 15-char name, 3: empty string */
	int br_mode;                   /* 0: NULL, 1: "brlan0", 2: 15-char name, 3: empty string */
	int rm_ret, cr_ret;            /* results of the two helpers */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wsb_case_t;
extern hwr_wsb_case_t sg_wifi_hal_add_station_bridge_suite[];
extern "C" void run_all_tests_sg_wifi_hal_add_station_bridge(void);
#endif
