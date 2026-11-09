/*
 * HANDLER: wifi_drv_get_phy_eht_cap_mac (platform/raspberry-pi)
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/raspberry-pi/platform_pi.c:672-676 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub: both arguments are
 * cast to void, nothing is read, written or logged.  (The banana-pi version parses the attribute and had NULL-pointer findings #122 / #123; the intel version
 * only logs "not implemented"; the qualcomm version had #134-#136.  This one cannot fail.)  No finding, no fix switch.  Renamed
 * hwr_rp_wifi_drv_get_phy_eht_cap_mac because the other platforms define the same name.
 *
 * Scaffolding only: struct eht_capabilities comes from hwr_gem.h.
 */
#include "hwr_rhe.h"

#define wifi_drv_get_phy_eht_cap_mac hwr_rp_wifi_drv_get_phy_eht_cap_mac

/* --- platform_pi.c:672-676 --- */
extern "C" {
void wifi_drv_get_phy_eht_cap_mac(struct eht_capabilities *eht_capab, struct nlattr **tb)
{
    (void)eht_capab;
    (void)tb;
}
}
