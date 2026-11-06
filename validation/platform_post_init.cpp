/*
 * HANDLER: platform_post_init
 *
 * Function copied from rdk-wifi-hal: platform/banana-pi/platform.c:109 (~/Desktop/G/rdk-wifi-hal).  This file holds ONLY
 * THE FIXED code: it carries FIX 1 below. system() is replaced by hwr_ppo_system (records the command, fails on
 * request); the prints are the real macros over the log sink.  The function is renamed hwr_platform_post_init because
 * the other platforms define the same name.
 */
#include "hwr_ppo.h"
#include <stdio.h>
#include <stdlib.h>


#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define system                             hwr_ppo_system
#define platform_post_init                 hwr_platform_post_init

/* --- platform.c:109 --- */
extern "C" {
int platform_post_init(wifi_vap_info_map_t *vap_map)
{
    /* FIX 1: the three system("brctl addif ...") results were ignored, so the function returned 0 although an interface
     * could not be added to the bridge (nothing in the log either).  Every command is still run, each failure is
     * logged, and -1 is returned when any failed.  (wifi_hal_post_init() in src/wifi_hal.c discards the result too and
     * has to forward it.) */
    int ret = 0;

    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    if (system("brctl addif brlan0 wifi0") != 0) {
        wifi_hal_error_print("%s:%d brctl wifi0 failed\n",__func__,__LINE__);
        ret = -1;
    }
    if (system("brctl addif brlan0 wifi1") != 0) {
        wifi_hal_error_print("%s:%d brctl wifi1 failed\n",__func__,__LINE__);
        ret = -1;
    }
    if (system("brctl addif brlan0 wifi2") != 0) {
        wifi_hal_error_print("%s:%d brctl wifi2 failed\n",__func__,__LINE__);
        ret = -1;
    }
    return ret;
}
}
