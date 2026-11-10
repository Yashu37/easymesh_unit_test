/*
 * HANDLER: wifi_hal_getApAclDeviceNum (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:2365-2372 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It returns an error for a NULL aclCount and otherwise
 * returns RETURN_ERR when wifi_drv_getApAclDeviceNum(apIndex, aclCount) returns non-zero, else RETURN_OK.
 *
 * Scaffolding only: wifi_drv_getApAclDeviceNum is a recording stub over the runner's world; the *_print macros go to the log sink hwr_print.  Renamed hwr_sg_wifi_hal_getApAclDeviceNum.
 */
#include "hwr_wgn.h"
#include <stdio.h>
#include <string.h>

#define wifi_hal_dbg_print(format, ...)          hwr_print(0, format, ##__VA_ARGS__)
#define wifi_drv_getApAclDeviceNum hwr_wgn_wifi_drv_getApAclDeviceNum
#define wifi_hal_getApAclDeviceNum hwr_sg_wifi_hal_getApAclDeviceNum

hwr_wgn_world_t hwr_wgn_world;

extern "C" {
int wifi_drv_getApAclDeviceNum(int vap_index, uint *acl_count)
{
    hwr_wgn_world.calls++; hwr_wgn_world.last_vap_index = vap_index; hwr_wgn_world.last_ptr = acl_count;
    if (hwr_wgn_world.ret == 0) *acl_count = hwr_wgn_world.value;
    return hwr_wgn_world.ret;
}

/* --- wifi_hal.c:2365-2372 --- */
INT wifi_hal_getApAclDeviceNum(INT apIndex, uint *aclCount)
{
    if (aclCount == NULL) {
        wifi_hal_dbg_print("%s:%d: aclCount is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    return wifi_drv_getApAclDeviceNum(apIndex, aclCount) ? RETURN_ERR : RETURN_OK;
}
}
