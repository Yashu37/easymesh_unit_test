/* hwr_whi.h - plumbing for the sg_wifi_hal_init harness (src/wifi_hal.c).
 * g_wifi_hal / wifi_radio_info_t are minimal STAND-INS with the members wifi_hal_init uses; every driver / netlink / hostapd helper it calls is a stub over runner data. */
#ifndef HWR_WHI_H
#define HWR_WHI_H
#include "hwr_defs.h"
#include <pthread.h>
#include <stdbool.h>
#define HWR_WHI_MAXR 6
typedef struct { unsigned int index; unsigned int rdk_radio_index; bool radio_presence; } hwr_whi_radio_t;
typedef struct {
	pthread_mutexattr_t hapd_lock_attr; pthread_mutex_t hapd_lock, nl_create_socket_lock, steering_data_lock;
	void *netlink_socket_map; int nl_event_fd; pthread_t nl_tid;
	unsigned int num_radios; int platform_flags;
	hwr_whi_radio_t radio_info[HWR_WHI_MAXR];
} hwr_whi_hal_t;
typedef struct {
	hwr_whi_hal_t hal;
	char trace[256];                               /* ordered list of the stub calls (one token each) */
	int drv_null, lsmod_false, init_ret, eco_ret, prim_ret, rinfo_ret, eloop_ret, pthr_ret, eap_ret, upd_fail_radio, chan_ret, caps_fn, flags_fn;
	int lsmod_calls;
} hwr_whi_world_t;
extern hwr_whi_world_t hwr_whi_world;
extern "C" int hwr_sg_wifi_hal_init(void);
typedef struct {
	const char *test_name;
	unsigned nrad;
	int shift;                     /* radio k has rdk_radio_index k + shift (shift != 0: get_radio_by_rdk_index(0) is NULL) */
	unsigned present;              /* bit k: radio k is present (not sleeping in ECO mode) */
	int drv_null;                  /* get_wifi_drv_name() returns NULL */
	int lsmod_false;               /* lsmod_by_name() answers false this many times first */
	int init_ret, eco_ret, prim_ret, rinfo_ret, eloop_ret, pthr_ret, eap_ret;
	int upd_fail_radio;            /* update_hostap_interfaces() fails for this radio (-1: never) */
	int chan_ret;
	int caps_fn, flags_fn;         /* the platform radio-caps / flags-init hooks exist */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_whi_case_t;
extern hwr_whi_case_t sg_wifi_hal_init_suite[];
extern "C" void run_all_tests_sg_wifi_hal_init(void);
#endif
