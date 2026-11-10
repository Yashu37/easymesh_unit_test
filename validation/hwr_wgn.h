/* hwr_wgn.h - plumbing for the sg_wifi_hal_getApAclDeviceNum harness (src/wifi_hal.c).
 * The function only checks aclCount and forwards to wifi_drv_getApAclDeviceNum(); that driver call is a recording stub over runner data (it writes *acl_count only on success). */
#ifndef HWR_WGN_H
#define HWR_WGN_H
#include "hwr_defs.h"
#include <sys/types.h>
typedef struct {
	int calls, last_vap_index;
	uint *last_ptr;
	int ret;                       /* what the driver call returns */
	uint value;                    /* written to *acl_count when ret == 0 */
} hwr_wgn_world_t;
extern hwr_wgn_world_t hwr_wgn_world;
extern "C" int hwr_sg_wifi_hal_getApAclDeviceNum(INT apIndex, uint *aclCount);
typedef struct {
	const char *test_name;
	int apIndex;
	int null_count;                /* aclCount is NULL */
	int drv_ret;                   /* result of wifi_drv_getApAclDeviceNum */
	uint drv_value;                /* the count it reports on success */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wgn_case_t;
extern hwr_wgn_case_t sg_wifi_hal_getApAclDeviceNum_suite[];
extern "C" void run_all_tests_sg_wifi_hal_getApAclDeviceNum(void);
#endif
