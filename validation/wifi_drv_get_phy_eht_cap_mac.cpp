/*
 * HANDLER: wifi_drv_get_phy_eht_cap_mac
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/banana-pi/platform.c:1035-1043 (~/Desktop/G/rdk-wifi-hal), including its
 * #if defined(CONFIG_IEEE80211BE) guard (defined below).  This file holds the FIXED code: the change sits between "start fix 1" / "end fix 1" (the unfixed copy is the reproducer commit).  Renamed
 * hwr_wifi_drv_get_phy_eht_cap_mac because the other platforms define the same name.
 *
 * Scaffolding only: struct eht_capabilities (hwr_gem.h, copied from hostap driver.h), u8 and WPA_GET_LE16 (hostap common.h:224).  struct nlattr, nla_data
 * and nla_len are the real libnl ones.
 */
#include "hwr_gem.h"

#define CONFIG_IEEE80211BE 1
typedef unsigned char u8;
static inline unsigned short WPA_GET_LE16(const u8 *a) { return (a[1] << 8) | a[0]; }
#define wifi_drv_get_phy_eht_cap_mac hwr_wifi_drv_get_phy_eht_cap_mac

/* --- platform.c:1034-1044 --- */
extern "C" {
#if defined(CONFIG_IEEE80211BE)
void wifi_drv_get_phy_eht_cap_mac(struct eht_capabilities *eht_capab, struct nlattr **tb)
{
    /* start fix 1 */
    if (eht_capab == NULL || tb == NULL) {
        return;
    }
    /* end fix 1 */

    if (tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC] &&
        nla_len(tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC]) >= 2) {
        const u8 *pos;

        pos = nla_data(tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC]);
        eht_capab->mac_cap = WPA_GET_LE16(pos);
    }
}
#endif /* CONFIG_IEEE80211BE */
}
