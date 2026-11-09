/*
 * HANDLER: wifi_setApMacAddressControlMode (platform/raspberry-pi)
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/raspberry-pi/platform_pi.c:383-410 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code: no fix is
 * applied.  It looks the VAP interface up by index (RETURN_ERR + error line when missing) and, for an AP-mode VAP, maps filterMode 0 -> filter disabled / black
 * list, 1 -> enabled / white list, 2 -> enabled / black list; any other filterMode (and any non-AP VAP) leaves the VAP unchanged and still returns RETURN_OK.
 * (The intel version of this function is an empty stub returning RETURN_OK; the banana-pi one is not defined here.)
 *
 * DESIGN NOTE (not counted): an unknown filterMode (3, -1, 255, ...) is silently accepted with RETURN_OK and nothing is applied.
 *
 * Scaffolding only: wifi_interface_info_t is rmc_iface_t (real wifi_vap_info_t member); get_interface_by_vap_index is a runner-controlled lookup that answers
 * from a copy of the VAP index; the print macros map to the log sink hwr_print (runner-poisoned slot).  Renamed hwr_rp_wifi_setApMacAddressControlMode because the
 * other platforms define the same name.
 */
#include "hwr_rmc.h"

#define wifi_interface_info_t rmc_iface_t
#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define wifi_setApMacAddressControlMode hwr_rp_wifi_setApMacAddressControlMode

hwr_rmc_world_t hwr_rmc_world;

static rmc_iface_t *get_interface_by_vap_index(unsigned int vap_index)
{
	hwr_rmc_world.lookups++; hwr_rmc_world.last_lookup = (int)vap_index;
	return (hwr_rmc_world.iface != NULL && hwr_rmc_world.iface_vap == (int)vap_index) ? hwr_rmc_world.iface : NULL;
}

/* --- platform_pi.c:383-410 --- */
extern "C" {
INT wifi_setApMacAddressControlMode(INT apIndex, INT filterMode)
{
    wifi_vap_info_t *vap_info = NULL;
    wifi_interface_info_t *interface = NULL;

    interface = get_interface_by_vap_index(apIndex);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: interface for ap index:%d not found\n", __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

    vap_info = &interface->vap_info;

    if (vap_info->vap_mode == wifi_vap_mode_ap) {
        if (filterMode == 0) {
               vap_info->u.bss_info.mac_filter_enable = FALSE;
               vap_info->u.bss_info.mac_filter_mode  = wifi_mac_filter_mode_black_list;
        } else if(filterMode == 1) {
               vap_info->u.bss_info.mac_filter_enable = TRUE;
               vap_info->u.bss_info.mac_filter_mode  = wifi_mac_filter_mode_white_list;
        } else if(filterMode == 2) {
               vap_info->u.bss_info.mac_filter_enable = TRUE;
               vap_info->u.bss_info.mac_filter_mode  = wifi_mac_filter_mode_black_list;
        }
    }

    return RETURN_OK;
}
}
