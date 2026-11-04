/* hwr_gsg.h - types / plumbing for the wifi_hal_steering_setGroup harness */
#ifndef HWR_GSG_H
#define HWR_GSG_H
#include "hwr_defs.h"
#include <pthread.h>
#include <stdint.h>
/* layouts of wifi_hal_priv.h, with the REAL wifi_steering_apConfig_t and MAX_NUM_RADIOS */
typedef struct { wifi_steering_apConfig_t config; } hwr_bm_info_t;
typedef struct { uint32_t group_index; uint32_t group_enable; hwr_bm_info_t bm_group_info[MAX_NUM_RADIOS]; } hwr_bm_group_t;
typedef struct { hwr_bm_group_t bm_steer_groups[8]; pthread_mutex_t steering_data_lock; } hwr_gsg_world_t;
extern hwr_gsg_world_t hwr_gsg_world;
extern "C" INT hwr_wifi_hal_steering_setGroup(UINT steeringgroupIndex, wifi_steering_apConfig_t *cfg_2, wifi_steering_apConfig_t *cfg_5);   /* renamed, see the handler file */

typedef struct { int ap; unsigned util_int; unsigned util_cnt; unsigned inact_int; unsigned inact_thr; } hwr_gsg_cfg_t;
typedef struct {
	const char *test_name;
	unsigned group; hwr_gsg_cfg_t c2, c5;
	unsigned null_mask;            /* 1 cfg_2, 2 cfg_5 passed as NULL, 4 cfg_5 is the same pointer as cfg_2 */
	unsigned acl_fail_mask;        /* 1: steering_set_acl_mode fails for cfg_2's apIndex, 2: for cfg_5's */
	int calls; int check_log;
	int expected_ret;
	int expected_enabled;          /* group_enable of the target group afterwards (1 stored, 0 not stored / disabled) */
	int state_unchanged;           /* 1: nothing may be modified (validation failure) */
} hwr_gsg_case_t;
extern hwr_gsg_case_t wifi_hal_steering_setGroup_suite[];
extern "C" void run_all_tests_wifi_hal_steering_setGroup(void);
/* steering_set_acl_mode stub */
typedef struct { int calls; uint32_t ap[4]; uint32_t mode[4]; } hwr_gsg_rec_t;
extern hwr_gsg_rec_t hwr_gsg_rec;
#define HWR_GSG_NOFAIL 0x7ABCDEF1
void hwr_gsg_configure(int fail_ap_a, int fail_ap_b);      /* HWR_GSG_NOFAIL = none */
#endif
