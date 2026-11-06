/*
 * HANDLER: wifi_hal_steering_setGroup
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc_wifi_wrappers.c:308-343 (~/Desktop/G/rdk-wifi-hal).  This
 * file holds ONLY THE FIXED code: it carries FIX 1 below.
 *
 * Scaffolding only: g_wifi_hal holds just bm_steer_groups[MAX_STEERING_GROUP_NUM (8)] and steering_data_lock
 * (layouts as in wifi_hal_priv.h, with the REAL wifi_steering_apConfig_t and MAX_NUM_RADIOS); real pthread
 * mutex calls; steering_set_acl_mode is a stub in the construct file (configurable result, records its
 * arguments); the prints are the real macros over the log sink.  The function under test is renamed
 * hwr_wifi_hal_steering_setGroup (ipc_server_output already stubs the real name).
 */
#include "hwr_gsg.h"
#include <string.h>
#include <pthread.h>


#define MAX_STEERING_GROUP_NUM  8
#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define wifi_hal_info_print(format, ...)   hwr_print(0, format, ##__VA_ARGS__)
#define wifi_bm_steering_group_t       hwr_bm_group_t
#define wifi_bm_steering_group_info_t  hwr_bm_info_t
#define g_wifi_hal            hwr_gsg_world
#define wifi_hal_steering_setGroup hwr_wifi_hal_steering_setGroup

extern "C" int steering_set_acl_mode(uint32_t apIndex, uint32_t mac_filter_mode);   /* wifi_hal_priv.h:1266, stub in the construct file */

hwr_gsg_world_t hwr_gsg_world = { {}, PTHREAD_MUTEX_INITIALIZER };

//--------------------------------------------------------------------------------------------------
extern "C" {
INT wifi_hal_steering_setGroup( UINT steeringgroupIndex,
                                wifi_steering_apConfig_t *cfg_2,
                                wifi_steering_apConfig_t *cfg_5)
{
    if (steeringgroupIndex >= MAX_STEERING_GROUP_NUM) {
        wifi_hal_error_print("%s:%d: Wrong steering group Index:%d\n", __func__, __LINE__, steeringgroupIndex);
        return RETURN_ERR;
    } else if (cfg_2 == NULL || cfg_5 == NULL) {
        wifi_hal_error_print("%s:%d: Wrong steering group Index:%d config\n", __func__, __LINE__, steeringgroupIndex);
        return RETURN_ERR;
    }

    wifi_bm_steering_group_t *p_steer_group;
    p_steer_group = &g_wifi_hal.bm_steer_groups[steeringgroupIndex];

    pthread_mutex_lock(&g_wifi_hal.steering_data_lock);
    p_steer_group->group_index = steeringgroupIndex;
    p_steer_group->group_enable = true;
    memset(p_steer_group->bm_group_info, 0, (MAX_NUM_RADIOS * sizeof(wifi_bm_steering_group_info_t)));
    memcpy(&p_steer_group->bm_group_info[0].config, cfg_2, sizeof(wifi_steering_apConfig_t));
    memcpy(&p_steer_group->bm_group_info[1].config, cfg_5, sizeof(wifi_steering_apConfig_t));

    /* Macfilter deny mode set */
    /* FIX 1: the results were ignored, so the group stayed enabled and RETURN_OK was reported although the
     * deny-mode MAC filter could not be set on one of its APs (unknown VAP, STA VAP, filter mode configured by
     * the user, nl80211 failure): steering to that AP would then not block anything.  Disable the group and
     * report the error. */
    if (steering_set_acl_mode(cfg_2->apIndex, wifi_mac_filter_mode_black_list) != RETURN_OK ||
        steering_set_acl_mode(cfg_5->apIndex, wifi_mac_filter_mode_black_list) != RETURN_OK) {
        p_steer_group->group_enable = false;
        pthread_mutex_unlock(&g_wifi_hal.steering_data_lock);
        return RETURN_ERR;
    }
    wifi_hal_info_print("Wi-Fi steering ApGroup %d CFG: apidx=%d, %d, %d, %d, %d\n",
                            steeringgroupIndex, cfg_2->apIndex,
                            cfg_2->utilCheckIntervalSec, cfg_2->utilAvgCount,
                            cfg_2->inactCheckIntervalSec, cfg_2->inactCheckThresholdSec);
    wifi_hal_info_print("Wi-Fi steering ApGroup %d CFG: apidx=%d, %d, %d, %d, %d\n",
                            steeringgroupIndex, cfg_5->apIndex,
                            cfg_5->utilCheckIntervalSec, cfg_5->utilAvgCount,
                            cfg_5->inactCheckIntervalSec, cfg_5->inactCheckThresholdSec);
    pthread_mutex_unlock(&g_wifi_hal.steering_data_lock);
    return RETURN_OK;
}
}
