/*
 * HANDLER: wifi_hal_createVAP (src/wifi_hal.c)
 *
 * Function copied from rdk-wifi-hal (verbatim apart from fix 1): src/wifi_hal.c:1394-1782 (~/Desktop/G/rdk-wifi-hal), generic Linux build (no CONFIG_WIFI_EMULATOR, CONFIG_WIFI_EMULATOR_EXT_AGENT, BANANA_PI_PORT,
 * CONFIG_GENERIC_MLO, VNTXER5_PORT, TARGET_GEMINI7_2, NL80211_ACL, EASY_MESH_NODE or BEACON_PROT).  This file holds the ORIGINAL code with fix 1 applied (start fix 1 / end fix 1 markers; the unfixed copy is the reproducer).  It validates the radio index and map, runs the platform
 * pre-create hook, then for every vap of the map (map->num_vaps entries of map->vap_array): validates an AP vap, finds or creates its interface, copies the vap into it, sets the mode / bridge / hostapd
 * parameters / MAC filter, starts the BSS when the radio is configured and enabled; finally it runs the platform post-create hook and returns the last start_bss / enable result.
 *
 * Scaffolding only: the stand-in radio / interface structures (hwr_wcv.h), recording stubs for every callee (nl80211, hostapd, platform hooks, vendor HAL), validate_wifi_interface_vap_info_params as a
 * short stand-in (an AP vap with an empty SSID is invalid, anything else valid; the real one is tested at its own entry), get_vap_bridge_name (src/wifi_hal_nl80211_utils.c:1563, verbatim).  The *_print
 * macros go to the log sink hwr_print.  Renamed hwr_sg_wifi_hal_createVAP.
 */
#include "hwr_wcv.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define wifi_hal_dbg_print(format, ...)          hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_info_print(format, ...)         hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)        hwr_print(1, format, ##__VA_ARGS__)

#define get_radio_by_rdk_index hwr_wcv_get_radio_by_rdk_index
#define get_platform_pre_create_vap_fn hwr_wcv_get_platform_pre_create_vap_fn
#define get_platform_create_vap_fn hwr_wcv_get_platform_create_vap_fn
#define get_platform_set_beacon_prot_fn hwr_wcv_get_platform_set_beacon_prot_fn
#define validate_wifi_interface_vap_info_params hwr_wcv_validate_wifi_interface_vap_info_params
#define get_interface_by_vap_index hwr_wcv_get_interface_by_vap_index
#define nl80211_create_interface hwr_wcv_nl80211_create_interface
#define wifi_hal_get_interface_name hwr_wcv_wifi_hal_get_interface_name
#define nl80211_interface_enable hwr_wcv_nl80211_interface_enable
#define nl80211_remove_from_bridge hwr_wcv_nl80211_remove_from_bridge
#define get_sta_4addr_status hwr_wcv_get_sta_4addr_status
#define nl80211_update_interface hwr_wcv_nl80211_update_interface
#define nl80211_retry_interface_enable hwr_wcv_nl80211_retry_interface_enable
#define nl80211_create_bridge hwr_wcv_nl80211_create_bridge
#define update_hostap_interface_params hwr_wcv_update_hostap_interface_params
#define start_bss hwr_wcv_start_bss
#define reload_vap_configuration hwr_wcv_reload_vap_configuration
#define update_hostap_interfaces hwr_wcv_update_hostap_interfaces
#define wifi_hal_get_mbssid_tx_interface hwr_wcv_wifi_hal_get_mbssid_tx_interface
#define wifi_hal_configure_mbssid hwr_wcv_wifi_hal_configure_mbssid
#define wifi_drv_set_operstate hwr_wcv_wifi_drv_set_operstate
#define get_vap_bridge_name hwr_wcv_get_vap_bridge_name
#define wifi_setApMacAddressControlMode hwr_wcv_wifi_setApMacAddressControlMode
#define re_configure_steering_mac_list hwr_wcv_re_configure_steering_mac_list
#define wifi_setApManagementFramePowerControl hwr_wcv_wifi_setApManagementFramePowerControl
#define wifi_hal_createVAP hwr_sg_wifi_hal_createVAP

/* src/wifi_hal.c:62-94 (non-emulator variant) */
#define RADIO_INDEX_ASSERT_RC(radioIndex, retcode) \
    do { \
        int _index = (int)radioIndex; \
        if ((_index >= (MAX_NUM_RADIOS)) || (_index < 0)) { \
            wifi_hal_error_print("%s: INCORRECT radioIndex = %d numRadios = %d\n", \
                    __FUNCTION__, _index, MAX_NUM_RADIOS); \
            return retcode; \
        } \
    } while (0)
#define NULL_PTR_ASSERT_RC(ptr, retcode) \
    do { \
        if (NULL == ptr) { \
            wifi_hal_error_print("%s:%d NULL pointer!\n", __FUNCTION__, __LINE__); \
            return retcode; \
        } \
    } while (0)
#define RADIO_INDEX_ASSERT(radioIndex)  RADIO_INDEX_ASSERT_RC(radioIndex, WIFI_HAL_INVALID_ARGUMENTS)
#define NULL_PTR_ASSERT(ptr)            NULL_PTR_ASSERT_RC(ptr, WIFI_HAL_INVALID_ARGUMENTS)

hwr_wcv_world_t hwr_wcv_world;

extern "C" {
wifi_radio_info_t *get_radio_by_rdk_index(unsigned int index)
{
    if (hwr_wcv_world.no_radio || index >= HWR_WCV_MAXR) return NULL;
    return &hwr_wcv_world.radios[index];
}
static int pre_hook(wifi_radio_index_t i, wifi_vap_info_map_t *m) { hwr_wcv_world.c_pre++; return 0; }
static int post_hook(wifi_radio_index_t i, wifi_vap_info_map_t *m) { hwr_wcv_world.c_post++; return 0; }
static int beacon_hook(int vap, int on) { return 0; }
platform_pre_create_vap_t get_platform_pre_create_vap_fn(void) { return hwr_wcv_world.pre_fn ? pre_hook : NULL; }
platform_create_vap_t get_platform_create_vap_fn(void) { return hwr_wcv_world.post_fn ? post_hook : NULL; }
platform_set_beacon_prot_t get_platform_set_beacon_prot_fn(void) { return hwr_wcv_world.beacon_fn ? beacon_hook : NULL; }
int validate_wifi_interface_vap_info_params(wifi_vap_info_t *vap_info, char *msg, int len)
{
    memset(msg, 0, len);
    if (vap_info->u.bss_info.ssid[0] == 0) { snprintf(msg, len, " ssid is NULL"); return RETURN_ERR; }
    return RETURN_OK;
}
wifi_interface_info_t *get_interface_by_vap_index(unsigned int vap_index)
{
    if (vap_index >= HWR_WCV_MAXI || !hwr_wcv_world.exists[vap_index]) return NULL;
    return &hwr_wcv_world.ifs[vap_index];
}
int nl80211_create_interface(wifi_radio_info_t *radio, wifi_vap_info_t *vap, wifi_interface_info_t **interface)
{
    hwr_wcv_world.c_create++;
    if (hwr_wcv_world.create_mode == 1) return -1;
    if (hwr_wcv_world.create_mode == 2) { *interface = NULL; return 0; }
    hwr_wcv_world.exists[vap->vap_index] = 1;
    *interface = &hwr_wcv_world.ifs[vap->vap_index];
    return 0;
}
char *wifi_hal_get_interface_name(wifi_interface_info_t *interface) { return interface->name; }
int nl80211_interface_enable(const char *name, bool enable)
{
    if (hwr_wcv_world.bridge_fail == 2 && strncmp(name, "br", 2) == 0) return -1;
    return 0;
}
int nl80211_remove_from_bridge(const char *name) { hwr_wcv_world.c_remove_bridge++; return 0; }
int get_sta_4addr_status(bool *sta_4addr) { *sta_4addr = true; return RETURN_OK; }
int nl80211_update_interface(wifi_interface_info_t *interface)
{
    hwr_wcv_world.c_update++;
    return hwr_wcv_world.update_fail_at == hwr_wcv_world.c_update ? -1 : 0;
}
int nl80211_retry_interface_enable(wifi_interface_info_t *interface, bool enable) { return 0; }
int nl80211_create_bridge(const char *name, const char *bridge) { hwr_wcv_world.c_bridge++; return hwr_wcv_world.bridge_fail == 1 ? -1 : 0; }
int update_hostap_interface_params(wifi_interface_info_t *interface) { hwr_wcv_world.c_hostap_if++; return hwr_wcv_world.hostap_if_fail ? -1 : 0; }
int start_bss(wifi_interface_info_t *interface) { hwr_wcv_world.c_start++; return hwr_wcv_world.start_ret; }
int reload_vap_configuration(wifi_interface_info_t *interface) { hwr_wcv_world.c_reload++; return hwr_wcv_world.reload_ret; }
int update_hostap_interfaces(wifi_radio_info_t *radio) { hwr_wcv_world.c_hostapd_ifs++; return hwr_wcv_world.hostapd_ifs_fail ? -1 : 0; }
wifi_interface_info_t *wifi_hal_get_mbssid_tx_interface(wifi_radio_info_t *radio) { return hwr_wcv_world.tx_other ? &hwr_wcv_world.ifs[HWR_WCV_MAXI - 1] : NULL; }
int wifi_hal_configure_mbssid(wifi_radio_info_t *radio) { hwr_wcv_world.c_mbssid++; return 0; }
int wifi_drv_set_operstate(wifi_interface_info_t *interface, int state) { hwr_wcv_world.c_operstate++; return 0; }
/* src/wifi_hal_nl80211_utils.c:1563-1566 verbatim */
const char *
get_vap_bridge_name(wifi_vap_info_t *vap)
{
    return (vap->u.sta_info.ignite_enabled) ? vap->repurposed_bridge_name : vap->bridge_name;
}
int wifi_setApMacAddressControlMode(unsigned int vap_index, int mode) { hwr_wcv_world.c_macctl++; hwr_wcv_world.last_filtermode = mode; return hwr_wcv_world.mac_ret; }
void re_configure_steering_mac_list(wifi_interface_info_t *interface) { hwr_wcv_world.c_steer++; }
int wifi_setApManagementFramePowerControl(int vap_index, int power) { hwr_wcv_world.c_power++; return 0; }

/* --- wifi_hal.c:1394-1782 --- */
INT wifi_hal_createVAP(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface, *mbssid_tx_interface;
    wifi_vap_info_t *vap;
    platform_pre_create_vap_t pre_set_vap_params_fn;
    platform_create_vap_t set_vap_params_fn;
    platform_set_beacon_prot_t set_vap_beacon_prot_fn;
    unsigned int i;
    char msg[2048];
    int ret = RETURN_OK;
#ifdef NL80211_ACL
    int set_acl = 0;
#else
    int filtermode;
#endif
    //bssid_t null_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
#if defined(VNTXER5_PORT) || defined(TARGET_GEMINI7_2)
#ifdef CONFIG_MLO
    char mld_ifname[32];
#endif 
#endif
    char *interface_name = NULL;

    RADIO_INDEX_ASSERT(index);
    NULL_PTR_ASSERT(map);

    /* ---------- start fix 1: map->num_vaps was not checked against the vap_array size, so the loop below read (and
     * wrote the bssid / mac of) vap_array[MAX_NUM_VAP_PER_RADIO ...] beyond the map. */
    if (map->num_vaps > (sizeof(map->vap_array) / sizeof(map->vap_array[0]))) {
        wifi_hal_error_print("%s:%d: radio index:%d num_vaps:%u exceeds the vap array size:%u\n", __func__, __LINE__,
            index, map->num_vaps, (unsigned int)(sizeof(map->vap_array) / sizeof(map->vap_array[0])));
        return WIFI_HAL_INVALID_ARGUMENTS;
    }
    /* ---------- end fix 1 */

    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d: radio index:%d failed not find radio\n", __func__, __LINE__,
            index);
        return RETURN_ERR;
    }
#ifndef CONFIG_WIFI_EMULATOR
    if (false == radio->radio_presence) {
       wifi_hal_info_print("%s:%d: radio index:%d skip vap create due to ECO mode\n", __func__,
           __LINE__, radio->index);
       return RETURN_OK;
    }
#endif
    if ((pre_set_vap_params_fn = get_platform_pre_create_vap_fn()) != NULL) {
        wifi_hal_info_print("%s:%d: radio index:%d pre-create vap\n", __func__, __LINE__,
            radio->index);
        pre_set_vap_params_fn(index, map);
    }

    // now create vaps on the interfaces
    for (i = 0; i < map->num_vaps; i++) {
        vap = &map->vap_array[i];

        wifi_hal_info_print("%s:%d: vap index:%d vap_name = %s create vap\n", __func__, __LINE__,
            vap->vap_index, vap->vap_name);

        if (vap->vap_mode == wifi_vap_mode_ap) {
            if (validate_wifi_interface_vap_info_params(vap, msg, sizeof(msg)) != RETURN_OK) {
                wifi_hal_error_print("%s:%d:Failed to validate interface vap_info params for vap_index: %d on radio index: %d. %s\n", __func__, __LINE__, vap->vap_index, index, msg);
                return WIFI_HAL_INVALID_ARGUMENTS;
            }
        }

        interface = get_interface_by_vap_index(vap->vap_index);
        if (interface == NULL) {
            wifi_hal_info_print("%s:%d:vap index:%d vap_name = %s create interface\n", __func__, __LINE__,
                vap->vap_index, vap->vap_name);
            if ((nl80211_create_interface(radio, vap, &interface) != 0) || (interface == NULL)) {
                wifi_hal_error_print("%s:%d: vap index:%d failed to create interface\n", __func__,
                    __LINE__, vap->vap_index);
                continue;
            }
        }

#ifdef NL80211_ACL
        if ((vap->u.bss_info.enabled == 1) &&
            ((vap->u.bss_info.mac_filter_enable == TRUE) ||
             (interface->vap_info.u.bss_info.mac_filter_enable != vap->u.bss_info.mac_filter_enable))) {
            set_acl = 1;
        }
#endif

#if defined(VNTXER5_PORT) || defined(TARGET_GEMINI7_2)
#ifdef CONFIG_MLO
        if (platform_set_intf_mld_bonding(radio, interface) != RETURN_OK) {
            wifi_hal_error_print("%s:%d: vap index:%d failed to create bonding\n", __func__, __LINE__,
                vap->vap_index);
            continue;
        }
#endif
#endif
        wifi_hal_info_print("%s:%d: vap index:%d mode:%d vap_name:%s\n", __func__, __LINE__,
            vap->vap_index, vap->vap_mode, vap->vap_name);
        if (vap->vap_mode == wifi_vap_mode_ap) {
            wifi_hal_info_print("%s:%d: vap_enable_status:%d\n", __func__, __LINE__, vap->u.bss_info.enabled);
            memcpy(vap->u.bss_info.bssid, interface->mac, sizeof(vap->u.bss_info.bssid));
        } else {
            wifi_hal_info_print("%s:%d: vap_enable_status:%d Ignite-vap-enable-status: %d\n", __func__, __LINE__, vap->u.sta_info.enabled,
                 vap->u.sta_info.ignite_enabled);
#if  !defined(CONFIG_WIFI_EMULATOR) && !defined(CONFIG_WIFI_EMULATOR_EXT_AGENT)
            memcpy(vap->u.sta_info.mac, interface->mac, sizeof(vap->u.sta_info.mac));
#else
            mac_addr_str_t sta_mac_str;
            char *key = NULL;
            memcpy(interface->mac, vap->u.sta_info.mac, sizeof(mac_address_t));
            memcpy(interface->vap_info.u.sta_info.mac, vap->u.sta_info.mac, sizeof(mac_address_t));
            key = to_mac_str(interface->vap_info.u.sta_info.mac, sta_mac_str);
            wifi_hal_dbg_print("%s:%d: sta mac is : %s\n", __func__, __LINE__, key);
#endif //!defined(CONFIG_WIFI_EMULATOR) || !defined(CONFIG_WIFI_EMULATOR_EXT_AGENT)
        }
        memcpy((unsigned char *)&interface->vap_info, (unsigned char *)vap, sizeof(wifi_vap_info_t));
        interface_name = wifi_hal_get_interface_name(interface);

#ifdef CONFIG_GENERIC_MLO
        // VAP down removes MLO links, so restrict down of interface to sta mode only
        if (vap->vap_mode == wifi_vap_mode_sta) {
#endif
            wifi_hal_info_print("%s:%d: interface:%s set down\n", __func__, __LINE__, interface->name);
            nl80211_interface_enable(interface->name, false);
#ifdef CONFIG_GENERIC_MLO
        }
#endif

#if  !defined(CONFIG_WIFI_EMULATOR) && !defined(CONFIG_WIFI_EMULATOR_EXT_AGENT)
        if (vap->vap_mode == wifi_vap_mode_sta) {
            bool sta_4addr = 0;
            wifi_hal_info_print("%s:%d: interface:%s remove from bridge\n", __func__, __LINE__,
                interface_name);
            nl80211_remove_from_bridge(interface_name);
            if (get_sta_4addr_status(&sta_4addr) == RETURN_OK) {
                interface->u.sta.sta_4addr = (int)sta_4addr;
            }
        }
#endif
        wifi_hal_info_print("%s:%d: interface:%s set mode:%d\n", __func__, __LINE__,
            interface_name, vap->vap_mode);
        if (nl80211_update_interface(interface) != 0) {
            wifi_hal_error_print("%s:%d: interface:%s failed to set mode %d\n",__func__, __LINE__,
                interface_name, vap->vap_mode);
            return RETURN_ERR;
        }

        wifi_hal_info_print("%s:%d: interface:%s radio configured:%d radio enabled:%d\n",
            __func__, __LINE__, interface_name, radio->configured, radio->oper_param.enable);
#ifdef CONFIG_GENERIC_MLO
        if (radio->oper_param.enable &&
            ((vap->vap_mode == wifi_vap_mode_sta) || radio->configured)) {
#else
        if (radio->configured && radio->oper_param.enable) {
#endif /* CONFIG_GENERIC_MLO */
            wifi_hal_info_print("%s:%d: interface:%s set up\n", __func__, __LINE__,
                interface_name);
            if (nl80211_interface_enable(interface_name, true) != 0) {
                ret = nl80211_retry_interface_enable(interface, true);
                if (ret != 0) {
                    wifi_hal_error_print("%s:%d: Retry of interface enable failed:%d\n", __func__,
                        __LINE__, ret);
                }
            }
        }

        if (vap->vap_mode == wifi_vap_mode_ap) {
            // create the bridge
            wifi_hal_info_print("%s:%d: interface:%s bss enabled:%d bridge:%s\n", __func__,
                __LINE__, interface_name, vap->u.bss_info.enabled, vap->bridge_name);
            if (vap->bridge_name[0] != '\0' && vap->u.bss_info.enabled) {
                wifi_hal_info_print("%s:%d: interface:%s create bridge:%s\n", __func__, __LINE__,
                    interface_name, vap->bridge_name);
#if (defined(VNTXER5_PORT) || defined(TARGET_GEMINI7_2)) && defined(CONFIG_MLO)
                if (radio->oper_param.variant & WIFI_80211_VARIANT_BE) {
                    snprintf(mld_ifname, sizeof(mld_ifname), "mld%d",  vap->vap_index);
                    if (nl80211_create_bridge(mld_ifname, vap->bridge_name) != 0) {
                        wifi_hal_error_print("%s:%d: interface:%s failed to create bridge:%s\n",
                            __func__, __LINE__, interface_name, vap->bridge_name);
                        continue;
                    }
                    wifi_hal_info_print("%s:%d: interface:%s set bridge %s up\n", __func__, __LINE__,
                         mld_ifname, vap->bridge_name);
                }
                else if (nl80211_create_bridge(interface_name, vap->bridge_name) != 0) {
#else
                if (nl80211_create_bridge(interface_name, vap->bridge_name) != 0) {
#endif
                    wifi_hal_error_print("%s:%d: interface:%s failed to create bridge:%s\n",
                        __func__, __LINE__, interface_name, vap->bridge_name);
                    continue;
                }
                wifi_hal_info_print("%s:%d: interface:%s set bridge %s up\n", __func__, __LINE__,
                    interface_name, vap->bridge_name);
                if (nl80211_interface_enable(vap->bridge_name, true) != 0) {
                    wifi_hal_error_print("%s:%d: interface:%s failed to set bridge %s up\n",
                        __func__, __LINE__, interface_name, vap->bridge_name);
                    continue;
                }
            }

            wifi_hal_info_print("%s:%d: interface:%s update hostapd params\n", __func__, __LINE__,
                interface_name);
            if (update_hostap_interface_params(interface) != RETURN_OK) {
                wifi_hal_error_print("%s:%d: interface:%s failed to update hostapd params\n",
                    __func__, __LINE__, interface_name);
                return RETURN_ERR;
            }

            wifi_hal_info_print("%s:%d: interface:%s vap_initialized:%d\n", __func__, __LINE__,
                interface_name, interface->vap_initialized);
            if (interface->vap_initialized == true) {
                wifi_hal_info_print("%s:%d: interface:%s bss_started:%d\n", __func__, __LINE__,
                    interface_name, interface->bss_started);
                if (!(interface->bss_started)) {
                    if (vap->u.bss_info.enabled && radio->configured && radio->oper_param.enable) {
                        wifi_hal_info_print("%s:%d: interface:%s enable ap\n", __func__,
                            __LINE__, interface_name);
                        interface->beacon_set = 0;
                        ret = start_bss(interface);
                        interface->bss_started = true;
                    }
                } else {
                    ret = reload_vap_configuration(interface);
                }
            } else {
                interface->vap_initialized = true;
                wifi_hal_info_print("%s:%d: radio index:%d update hostapd interfaces\n", __func__,
                    __LINE__, radio->index);
                if (update_hostap_interfaces(radio)!= RETURN_OK) {
                    wifi_hal_error_print("%s:%d: radio index:%d failed to update hostapd "
                        "interfaces\n", __func__, __LINE__, radio->index);
                    return RETURN_ERR;
                }
                if (vap->u.bss_info.enabled && radio->configured && radio->oper_param.enable) {
                    wifi_hal_info_print("%s:%d: interface:%s enable ap\n", __func__,
                        __LINE__, interface_name);
                    interface->beacon_set = 0;
                    ret = start_bss(interface);
                    interface->bss_started = true;
                }
            }
            if (radio->configured && radio->oper_param.enable) {
                wifi_hal_info_print("%s:%d: interface:%s set %s\n", __func__, __LINE__,
                    interface_name, vap->u.bss_info.enabled ? "up" : "down");
                nl80211_interface_enable(interface_name, vap->u.bss_info.enabled);
#if defined(VNTXER5_PORT) || defined(TARGET_GEMINI7_2)
#ifdef CONFIG_MLO
                if(radio->oper_param.variant & WIFI_80211_VARIANT_BE)
                {
                    snprintf(mld_ifname, sizeof(mld_ifname), "mld%d", vap->vap_index);
                    nl80211_interface_enable(mld_ifname, vap->u.bss_info.enabled);
                }
#endif
#endif
            }

            // set the vap mode on the interface
            interface->vap_info.vap_mode = vap->vap_mode;

            mbssid_tx_interface = wifi_hal_get_mbssid_tx_interface(radio);
            if (mbssid_tx_interface != NULL && mbssid_tx_interface != interface) {
                wifi_hal_configure_mbssid(radio);
            }

        } else if (vap->vap_mode == wifi_vap_mode_sta) {
#if defined(CONFIG_WIFI_EMULATOR)
            if (nl80211_create_bridge(interface_name, vap->bridge_name) != 0) {
                wifi_hal_error_print("%s:%d: interface:%s failed to create bridge:%s\n",
                        __func__, __LINE__, interface_name, vap->bridge_name);
            }

            nl80211_interface_enable(interface_name, false);
            nl80211_set_mac(interface);
            interface->vap_initialized = true;
            nl80211_interface_enable(interface_name, true);
            wifi_hal_info_print("%s:%d: interface:%s set operstate 1\n", __func__,
                    __LINE__, interface_name);
            wifi_drv_set_operstate(interface, 1);

            nl80211_interface_enable(interface_name, true);
#else
            //XXX set correct status after reconfigure and call conn status callback
            //nl80211_start_scan(interface);
            interface->vap_initialized = true;

            if (vap->u.sta_info.ignite_enabled) {
                if (nl80211_create_bridge(interface->name, get_vap_bridge_name(vap)) != 0) {
                    wifi_hal_error_print("%s:%d: interface:%s failed to create bridge:%s\n",
                        __func__, __LINE__, interface->name, get_vap_bridge_name(vap));
                    return RETURN_ERR;
                }
                wifi_hal_info_print("%s:%d: interface:%s set bridge %s up\n", __func__, __LINE__,
                    interface->name, get_vap_bridge_name(vap));
                if (nl80211_interface_enable(get_vap_bridge_name(vap), true) != 0) {
                    wifi_hal_error_print("%s:%d: interface:%s failed to set bridge %s up\n",
                        __func__, __LINE__, interface->name, get_vap_bridge_name(vap));
                    return RETURN_ERR;
                }
            }

#ifdef CONFIG_WIFI_EMULATOR_EXT_AGENT
            nl80211_interface_enable(interface->name, false);
            nl80211_set_mac(interface);
            nl80211_interface_enable(interface->name, true);
#endif
#ifdef CONFIG_GENERIC_MLO
        if (radio->oper_param.enable &&
            ((vap->vap_mode == wifi_vap_mode_sta) || radio->configured)) {
#else
            if (radio->configured && radio->oper_param.enable) {
#endif /* CONFIG_GENERIC_MLO */
                wifi_hal_info_print("%s:%d: interface:%s set operstate 1\n", __func__,
                    __LINE__, interface_name);
                wifi_drv_set_operstate(interface, 1);
                if (nl80211_interface_enable(interface->name, true) != 0) {
                    wifi_hal_error_print("%s:%d interface:%s failed to set bridge %s up\n",
                        __func__, __LINE__, interface->name, get_vap_bridge_name(vap));
                }
            } else {
                wifi_hal_info_print("%s:%d: interface:%s set down\n", __func__, __LINE__,
                    interface_name);
                nl80211_interface_enable(interface_name, false);
            }
#endif //CONFIG_WIFI_EMULATOR
        }

        if (vap->vap_mode == wifi_vap_mode_ap) {
#if defined(EASY_MESH_NODE)
            if (is_wifi_hal_vap_mesh_backhaul(vap->vap_index)) {
                interface->vap_info.u.bss_info.mac_filter_mode = wifi_mac_filter_mode_black_list;
            }
#endif // EASY_MESH_NODE
#ifdef NL80211_ACL
            if (set_acl == 1) {
                nl80211_set_acl(interface);
            }
#else
            //Call vendor HAL
            if (vap->u.bss_info.mac_filter_enable == TRUE) {
                if (vap->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_black_list) {
                    //blacklist
                    filtermode = 2;
                } else {
                    //whitelist
                    filtermode = 1;
                }
            } else {
                //disabled
                filtermode  = 0;
            }
            wifi_hal_info_print("%s:%d: vap index:%d set mac filter mode:%d\n", __func__, __LINE__,
                vap->vap_index, filtermode);
            if (wifi_setApMacAddressControlMode(vap->vap_index, filtermode) < 0) {
                wifi_hal_error_print("%s:%d: vap index:%d failed to set mac filter\n", __func__,
                    __LINE__, vap->vap_index);
                return RETURN_ERR;
            }
#endif // NL80211_ACL
            re_configure_steering_mac_list(interface);

            wifi_hal_info_print("%s:%d: vap index:%d set power:%d\n",  __func__, __LINE__,
                vap->vap_index, vap->u.bss_info.mgmtPowerControl);
            if (wifi_setApManagementFramePowerControl(vap->vap_index,
                vap->u.bss_info.mgmtPowerControl) != RETURN_OK) {
                wifi_hal_error_print("%s:%d: vap index:%d failed to set power %d\n", __func__,
                    __LINE__, vap->vap_index, vap->u.bss_info.mgmtPowerControl);
            }

            if ((set_vap_beacon_prot_fn = get_platform_set_beacon_prot_fn()) != NULL &&
                    interface->u.ap.iface.drv_flags & WPA_DRIVER_FLAGS_BEACON_PROTECTION) {
#ifdef BEACON_PROT
                wifi_hal_info_print("%s:%d: vap index:%d set beacon prot: %d\n", __func__, __LINE__,
                        vap->vap_index, interface->u.ap.conf.beacon_prot);
                set_vap_beacon_prot_fn(vap->vap_index, interface->u.ap.conf.beacon_prot);
#endif
            }
        }
#if defined(CONFIG_WIFI_EMULATOR) || defined(BANANA_PI_PORT)
        //Init wpa-supplicant params.
        if (vap->vap_mode == wifi_vap_mode_sta) {
            deinit_wpa_supplicant(interface);
            if (init_wpa_supplicant(interface) != RETURN_OK) {
                wifi_hal_info_print("%s:%d: Error initializing supplicant params\n", __func__, __LINE__);
            }
        }
#endif
    }

    if ((set_vap_params_fn = get_platform_create_vap_fn()) != NULL) {
        wifi_hal_info_print("%s:%d: radio index:%d post-create vap\n", __func__, __LINE__,
            radio->index);
        set_vap_params_fn(index, map);
    }

    return ret;
}
}
