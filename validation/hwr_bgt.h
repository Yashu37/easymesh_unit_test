/* hwr_bgt.h - plumbing for the broadcom wifi_getRadioTrafficStats2 harness (platform/broadcom) */
#ifndef HWR_BGT_H
#define HWR_BGT_H
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/attr.h>
#include <linux/nl80211.h>
#include "hso_hal_ipc.h"
#ifdef __cplusplus
#include "hwr_defs.h"
#else
void hwr_print(int level, const char *format, ...);
#endif

typedef struct { unsigned int index; unsigned int phy_index; } bgt_iface_t;
typedef struct { int rdk_index; bgt_iface_t *primary; } bgt_radio_t;

typedef struct {
    bgt_radio_t *radio; int cmd_fail, dump_rc, omit_reply, omit_attr;   /* omit_reply: 1 no vendor data, 2 no radio-info nest; omit_attr: radio-info attribute left out (0 none) */
    unsigned long long base;                                            /* value seed of the 21 statistics */
    int cmd_calls, send_calls;
} bgt_world_t;
extern bgt_world_t hwr_bgt_world;

#ifdef __cplusplus
extern "C" {
#endif
INT hwr_bcm_wifi_getRadioTrafficStats2(INT radioIndex, wifi_radioTrafficStats2_t *radioTrafficStats);
#ifdef __cplusplus
}
#endif

typedef struct {
    const char *test_name;
    int radio_index, has_radio, has_iface;
    int out_mode;                 /* 0 NULL output, 1 heap block of exactly sizeof(wifi_radioTrafficStats2_t) */
    unsigned long long base;
    int cmd_fail, dump_rc, omit_reply, omit_attr;
    int expected_ret, exp_untouched, calls, last;
} bgt_case_t;
extern bgt_case_t bcm_wifi_getRadioTrafficStats2_suite[];
#ifdef __cplusplus
extern "C" void run_all_tests_bcm_wifi_getRadioTrafficStats2(void);
#endif
#endif
