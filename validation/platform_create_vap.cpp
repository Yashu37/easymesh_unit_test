/*
 * HANDLER: platform_create_vap
 *
 * Function copied from rdk-wifi-hal: platform/banana-pi/platform.c:131 (~/Desktop/G/rdk-wifi-hal).  With RDK_PCV_FIX 0 it is the
 * VERBATIM original (reproduces the findings); with RDK_PCV_FIX 1 it carries FIX 1..3 below.
 * Collaborators: wifi_hal_is_mld_enabled is copied VERBATIM from src/wifi_hal_nl80211_utils.c:5872; for_each_mld_link is
 * hostapd's (hostapd.h:959, CONFIG_IEEE80211BE) over the verbatim dl_list macros; get_interface_by_vap_index,
 * ieee802_11_set_beacon and wifi_hal_get_interface_name are stubs (construct file) that look up the runner's interfaces, record the
 * link ids and fail on request.  HOSTAPD_VERSION is 211 (the function body is compiled out below that).  The prints are the
 * real macros over the log sink.  The function is renamed hwr_platform_create_vap (other platforms define the same name).
 */
#include "hwr_pcv.h"
#include <stdio.h>

/* 1 = with FIX 1..3, 0 = original unfixed function (set to 0 to reproduce the findings) */
#define RDK_PCV_FIX  1

#define HOSTAPD_VERSION 211
#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define for_each_mld_link(partner, self) \
	dl_list_for_each(partner, &self->mld->links, struct hostapd_data, link)
#define get_interface_by_vap_index         hwr_pcv_get_interface_by_vap_index
#define ieee802_11_set_beacon              hwr_pcv_set_beacon
#define wifi_hal_get_interface_name        hwr_pcv_get_interface_name
#define platform_create_vap                hwr_platform_create_vap

/* --- src/wifi_hal_nl80211_utils.c:5872 --- */
static
bool wifi_hal_is_mld_enabled(wifi_interface_info_t *interface)
{
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: NULL interface pointer\n", __func__, __LINE__);
        return false;
    }

    if (interface->vap_info.vap_mode == wifi_vap_mode_ap) {
        return interface->vap_info.u.bss_info.mld_info.common_info.mld_enable;
#if defined(CONFIG_IEEE80211BE) && defined(CONFIG_GENERIC_MLO)
    } else if (interface->vap_info.vap_mode == wifi_vap_mode_sta) {
        return (interface->mlo_params.valid_links > 0);
#endif /* CONFIG_IEEE80211BE & CONFIG_GENERIC_MLO */
    }

    return false;
}

/* --- platform.c:131 --- */
extern "C" {
#if RDK_PCV_FIX
int platform_create_vap(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
#if (HOSTAPD_VERSION >= 211)
    wifi_vap_info_t *vap;
    wifi_interface_info_t *interface;
    struct hostapd_data *hapd, *link_bss;

    /* FIX 1: map == NULL was dereferenced (map->num_vaps) - platform_pre_create_vap checks it, this function did not. */
    if (map == NULL) {
        wifi_hal_error_print("%s:%d: wifi_vap_info_map_t *map is NULL\n", __func__, __LINE__);
        return -1;
    }
    /* FIX 2: num_vaps was used as the loop bound without checking it against the size of vap_array
     * (MAX_NUM_VAP_PER_RADIO): a larger value read map->vap_array[i] behind the array (out-of-bounds read). */
    if (map->num_vaps > MAX_NUM_VAP_PER_RADIO) {
        wifi_hal_error_print("%s:%d: invalid num_vaps %u\n", __func__, __LINE__, map->num_vaps);
        return -1;
    }

    for (unsigned int i = 0; i < map->num_vaps; i++) {
        vap = &map->vap_array[i];
        if (vap->vap_mode != wifi_vap_mode_ap) {
            continue;
        }

        interface = get_interface_by_vap_index(vap->vap_index);
        if (interface == NULL) {
            wifi_hal_error_print("%s:%d: failed to get interface for vap_index %d\n", __func__,
                __LINE__, vap->vap_index);
            continue;
        }

        if (!interface->vap_info.u.bss_info.enabled) {
            continue;
        }

        if (interface->u.ap.conf.disable_11be) {
            continue;
        }

        if (!wifi_hal_is_mld_enabled(interface)) {
            continue;
        }

        /* beacon has to be set twice to make it broadcast */
        hapd = &interface->u.ap.hapd;
        /* FIX 3: for_each_mld_link() dereferences hapd->mld->links; an interface whose vap_info says mld_enable but whose
         * hostapd data has no MLD (not created / already freed) was a NULL dereference. */
        if (hapd->mld == NULL) {
            wifi_hal_error_print("%s:%d: no mld for vap_index %d\n", __func__, __LINE__, vap->vap_index);
            continue;
        }
        for_each_mld_link(link_bss, hapd) {
            if (ieee802_11_set_beacon(link_bss) != 0) {
                wifi_hal_error_print("%s:%d: Failed to set beacon for interface: %s link id: %d\n",
                    __func__, __LINE__, wifi_hal_get_interface_name(interface),
                    link_bss->mld_link_id);
                return -1;
            }
        }
    }
#endif
    return 0;
}
#else
int platform_create_vap(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
#if (HOSTAPD_VERSION >= 211)
    wifi_vap_info_t *vap;
    wifi_interface_info_t *interface;
    struct hostapd_data *hapd, *link_bss;

    for (unsigned int i = 0; i < map->num_vaps; i++) {
        vap = &map->vap_array[i];
        if (vap->vap_mode != wifi_vap_mode_ap) {
            continue;
        }

        interface = get_interface_by_vap_index(vap->vap_index);
        if (interface == NULL) {
            wifi_hal_error_print("%s:%d: failed to get interface for vap_index %d\n", __func__,
                __LINE__, vap->vap_index);
            continue;
        }

        if (!interface->vap_info.u.bss_info.enabled) {
            continue;
        }

        if (interface->u.ap.conf.disable_11be) {
            continue;
        }

        if (!wifi_hal_is_mld_enabled(interface)) {
            continue;
        }

        /* beacon has to be set twice to make it broadcast */
        hapd = &interface->u.ap.hapd;
        for_each_mld_link(link_bss, hapd) {
            if (ieee802_11_set_beacon(link_bss) != 0) {
                wifi_hal_error_print("%s:%d: Failed to set beacon for interface: %s link id: %d\n",
                    __func__, __LINE__, wifi_hal_get_interface_name(interface),
                    link_bss->mld_link_id);
                return -1;
            }
        }
    }
#endif
    return 0;
}
#endif
}
