/*
 * HANDLER: wifi_drv_get_phy_eht_cap_mac (platform/intel)
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/intel/platform.c:1965-1968 (~/Desktop/G/rdk-wifi-hal).  The intel version is a stub that only logs
 * "<func>:<line>: not implemented" and never touches eht_capab or tb (the banana-pi version parses the EHT MAC capability attribute; different code, already
 * harnessed with its own findings).  No finding, no fix switch.  Renamed hwr_int_wifi_drv_get_phy_eht_cap_mac because the other platforms define the same name.
 *
 * Scaffolding only: wifi_hal_error_print maps to the log sink hwr_print (runner-poisoned slot); struct eht_capabilities comes from hwr_gem.h.
 */
#include "hwr_ihe.h"

#define wifi_hal_error_print(format, ...) hwr_print(1, format, ##__VA_ARGS__)
#define wifi_drv_get_phy_eht_cap_mac hwr_int_wifi_drv_get_phy_eht_cap_mac

/* --- platform.c:1965-1968 --- */
extern "C" {
void wifi_drv_get_phy_eht_cap_mac(struct eht_capabilities *eht_capab, struct nlattr **tb)
{
    wifi_hal_error_print("%s:%d: not implemented\n", __func__, __LINE__);
}
}
