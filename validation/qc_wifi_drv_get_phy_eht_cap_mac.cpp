/*
 * HANDLER: wifi_drv_get_phy_eht_cap_mac (platform/qualcomm)
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/qualcomm/platform_ext.c:1124-1136 (platform_xer5.c:1405-1417 holds identical code) (~/Desktop/G/rdk-wifi-hal),
 * inside the file's #ifdef CONFIG_IEEE80211BE section (defined below).  This file holds the ORIGINAL code with fixes 1-2 applied
 * (start fix n / end fix n markers; the unfixed copy is the reproducer): fix 1 NULL checks, fix 2 &eht_capab->mac_cap.
 *
 * The function was written for a struct where mac_cap is a byte array, but in hostap (both hostap-2.10 and the OneWifi libhostap) struct eht_capabilities has
 * "u16 mac_cap".  os_memcpy(eht_capab->mac_cap, ...) therefore passes the 16-bit VALUE of mac_cap as the destination ADDRESS (integer-to-pointer conversion,
 * compiled here with -fpermissive): whenever the EHT MAC attribute carries data it writes to a bogus low address (0 .. 0xFFFF) and crashes.  It also dereferences
 * tb and, with an attribute present, eht_capab without a NULL check.  The banana-pi version of this function parses the attribute correctly.
 *
 * Scaffolding only: struct eht_capabilities (hwr_gem.h, copied from hostap driver.h), u8, os_memcpy (hostap os.h: plain memcpy); struct nlattr, nla_data and
 * nla_len are the real libnl ones.  Renamed hwr_qc_wifi_drv_get_phy_eht_cap_mac because the other platforms define the same name.
 */
#include "hwr_qem.h"
#include <string.h>

#define CONFIG_IEEE80211BE 1
typedef unsigned char u8;
#define os_memcpy memcpy
#define wifi_drv_get_phy_eht_cap_mac hwr_qc_wifi_drv_get_phy_eht_cap_mac

/* --- platform_ext.c:1124-1136 --- */
extern "C" {
#ifdef CONFIG_IEEE80211BE
void wifi_drv_get_phy_eht_cap_mac(struct eht_capabilities *eht_capab, struct nlattr **tb) {
    /* start fix 1 */
    if (eht_capab == NULL || tb == NULL) {
        return;
    }
    /* end fix 1 */
    if (tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC]) {
        size_t len;

        len = nla_len(tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC]);

        if (len > sizeof(eht_capab->mac_cap)) {
            len = sizeof(eht_capab->mac_cap);
        }
        /* start fix 2 */
        os_memcpy(&eht_capab->mac_cap,
                nla_data(tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC]), len);
        /* end fix 2 */
    }
}
#endif /* CONFIG_IEEE80211BE */
}
