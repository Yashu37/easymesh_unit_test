/*
 * HANDLER: platform_pre_create_vap
 *
 * Function copied from rdk-wifi-hal: platform/banana-pi/platform.c:304 (~/Desktop/G/rdk-wifi-hal).  This file holds ONLY
 * THE FIXED code: it carries the fixes described in its comments (plus the helper hwr_set_radius_defaults).  The
 * CONFIG_IEEE80211BE && CONFIG_GENERIC_MLO block is part of the verbatim text but compiled out (the macros are not
 * defined in this harness, as in the default banana-pi build of the libraries here). Collaborators:
 * wifi_nvram_defaultRead (stub with per-key values/results; its copy line is the original
 * strncpy(out,position,strlen(position)+1)), get_interface_by_vap_index / is_wifi_hal_vap_lnf_radius /
 * is_wifi_hal_vap_hotspot_secure (stubs driven by the runner) and get_security_mode_support_radius (VERBATIM copy of
 * src/wifi_hal_nl80211_utils.c, renamed).  The prints are the real macros over the log sink. Renamed
 * hwr_platform_pre_create_vap (other platforms define the same name).
 */
#include "hwr_ppv.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define BPI_LEN_32 32        /* platform.c */
#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define wifi_nvram_defaultRead             hwr_ppv_nvram
#define get_interface_by_vap_index         hwr_ppv_get_if
#define is_wifi_hal_vap_lnf_radius         hwr_ppv_is_lnf
#define is_wifi_hal_vap_hotspot_secure     hwr_ppv_is_hotspot
#define get_security_mode_support_radius   hwr_ppv_gsr
#define platform_pre_create_vap            hwr_platform_pre_create_vap

extern "C" {
/* --- src/wifi_hal_nl80211_utils.c (verbatim) --- */
int get_security_mode_support_radius(int mode)
{
    int sec_mode = 0;
    if ((mode == wifi_security_mode_wpa_enterprise) || (mode == wifi_security_mode_wpa2_enterprise ) || (mode == wifi_security_mode_wpa3_enterprise) || (mode == wifi_security_mode_wpa_wpa2_enterprise)){
        sec_mode = 1;
    } else {
        sec_mode = 0;
    }

    return sec_mode;
}

/* --- platform.c:304 --- */
/* FIX 1 + 3 helper: reads the three defaults into a 129-byte buffer (the reader writes up to 128 bytes) and applies each only when it is valid:
 *   ip   : 1..(ip_sz-1) characters      (was copied unbounded into the 45-byte ip / s_ip: overflowed port, key, identity ... )
 *   port : a number 1..65535            (atoi() into an unsigned short: 70000 -> 4464, -1 -> 65535, missing / invalid -> 0)
 *   key  : 1..(key_sz-1) characters     (was copied unbounded into the 64-byte key / s_key)
 * Otherwise the field keeps its current value. */
static void hwr_set_radius_defaults(unsigned char *ip, size_t ip_sz, unsigned short *port, char *key, size_t key_sz)
{
    char val[129];
    char *end = NULL;
    long p;

    memset(val, 0, sizeof(val));
    if (wifi_nvram_defaultRead("radius_s_ip", val) == 0 && val[0] != '\0' && strlen(val) < ip_sz) {
        memcpy(ip, val, strlen(val) + 1);
    } else {
        wifi_hal_error_print("%s:%d: no valid radius ip in nvram\n", __func__, __LINE__);
    }
    memset(val, 0, sizeof(val));
    if (wifi_nvram_defaultRead("radius_s_port", val) == 0 && (p = strtol(val, &end, 10), end != val) && p >= 1 && p <= 65535) {
        *port = (unsigned short)p;
    } else {
        wifi_hal_error_print("%s:%d: no valid radius port in nvram\n", __func__, __LINE__);
    }
    memset(val, 0, sizeof(val));
    if (wifi_nvram_defaultRead("radius_key", val) == 0 && val[0] != '\0' && strlen(val) < key_sz) {
        memcpy(key, val, strlen(val) + 1);
    } else {
        wifi_hal_error_print("%s:%d: no valid radius key in nvram\n", __func__, __LINE__);
    }
}

int platform_pre_create_vap(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
    /* FIX 1: output_val was BPI_LEN_32 (32 bytes) and received the nvram value of radius_s_port, which the reader copies with strlen+1 bytes
     *        (up to 128): a long value overflowed the stack buffer.  The values are now read by hwr_set_radius_defaults() into a 129-byte buffer. */
    int i = 0;
    wifi_vap_info_t *vap = NULL;
    wifi_interface_info_t *interface = NULL;

    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);

    if (map == NULL)
    {
        wifi_hal_dbg_print("%s:%d: wifi_vap_info_map_t *map is NULL \n", __func__, __LINE__);
        return -1;
    }
    /* FIX 2: num_vaps was not checked against the size of vap_array (MAX_NUM_VAP_PER_RADIO): both loops read vap_array[i] out of the map. */
    if (map->num_vaps > MAX_NUM_VAP_PER_RADIO) {
        wifi_hal_error_print("%s:%d: invalid number of vaps %u (max %d)\n", __func__, __LINE__, map->num_vaps, MAX_NUM_VAP_PER_RADIO);
        return -1;
    }
    for (i = 0; i < map->num_vaps; i++)
    {
        if (map->vap_array[i].vap_mode == wifi_vap_mode_ap)
        {
            if ((get_security_mode_support_radius(map->vap_array[i].u.bss_info.security.mode)) ||
                is_wifi_hal_vap_lnf_radius(map->vap_array[i].vap_index) ||
                is_wifi_hal_vap_hotspot_secure(map->vap_array[i].vap_index)) {
                /* Set Default Primary RADIUS Configurations if not already configured */
                if (strcmp(map->vap_array[i].u.bss_info.security.u.radius.ip, "0.0.0.0") == 0) {
                    hwr_set_radius_defaults(map->vap_array[i].u.bss_info.security.u.radius.ip, sizeof(map->vap_array[i].u.bss_info.security.u.radius.ip),
                        &map->vap_array[i].u.bss_info.security.u.radius.port, map->vap_array[i].u.bss_info.security.u.radius.key,
                        sizeof(map->vap_array[i].u.bss_info.security.u.radius.key));
                }
                /* Set Default Secondary RADIUS Configurations if not already configured */
                if (strcmp(map->vap_array[i].u.bss_info.security.u.radius.s_ip, "0.0.0.0") == 0) {
                    hwr_set_radius_defaults(map->vap_array[i].u.bss_info.security.u.radius.s_ip, sizeof(map->vap_array[i].u.bss_info.security.u.radius.s_ip),
                        &map->vap_array[i].u.bss_info.security.u.radius.s_port, map->vap_array[i].u.bss_info.security.u.radius.s_key,
                        sizeof(map->vap_array[i].u.bss_info.security.u.radius.s_key));
                }
                wifi_hal_dbg_print("%s:%d: Primary RADIUS server IP address:%s Port:%d \n Secondary RADIUS server IP address:%s Port:%d \n",
                    __func__, __LINE__, map->vap_array[i].u.bss_info.security.u.radius.ip, map->vap_array[i].u.bss_info.security.u.radius.port,
                    map->vap_array[i].u.bss_info.security.u.radius.s_ip, map->vap_array[i].u.bss_info.security.u.radius.s_port);
            }
        }
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

        if (interface->vap_info.vap_mode != wifi_vap_mode_ap) {
            continue;
        }

#if defined(CONFIG_IEEE80211BE) && defined(CONFIG_GENERIC_MLO)
        // Prevent modifications of MLD_Addr and link ID
        memcpy(vap->u.bss_info.mld_info.common_info.mld_addr,
            interface->vap_info.u.bss_info.mld_info.common_info.mld_addr, sizeof(mac_address_t));
        vap->u.bss_info.mld_info.common_info.mld_link_id =
            interface->vap_info.u.bss_info.mld_info.common_info.mld_link_id;

        if (has_config_changed(&interface->vap_info, vap) == false ||
            (interface->u.ap.conf.disable_11be == true) ||
            (interface->vap_info.vap_mode != wifi_vap_mode_ap)) {
            continue;
        }

        // Evaluate the current state vs incoming - do not alter incoming mld_enable or VAP enable
        bool is_mlo_enabled = interface->vap_info.u.bss_info.enabled && wifi_hal_is_mld_enabled(interface);
        bool should_enable_mlo = vap->u.bss_info.enabled && vap->u.bss_info.mld_info.common_info.mld_enable;

        // Verify the incoming params against current MLD state
        if (is_mlo_enabled == true && should_enable_mlo == false) {
            if (teardown_mlo_vap(interface) != 0) {
                wifi_hal_error_print("%s:%d: Failed to teardown link for MLD ID %d on VAP idx %d\n",
                    __func__, __LINE__, vap->u.bss_info.mld_info.common_info.mld_id,
                    vap->vap_index);
                return -1;
            }

            // Before possibly disabling MLD on interface, get the new first interface.
            // Currently OneWifi allows for improper config on Bpi where mld_enable is true
            // even if VAP has been disabled.
            wifi_interface_info_t *first_interface = wifi_hal_get_first_mld_interface(interface);

            // We need to update data now since at this point vap_info is not yet copied
            interface->vap_info.u.bss_info.mld_info.common_info.mld_enable =
                vap->u.bss_info.mld_info.common_info.mld_enable;
            interface->vap_info.u.bss_info.enabled = vap->u.bss_info.enabled;
            interface->vap_info.u.bss_info.mld_info.common_info.mld_link_id = UNDEFINED_MLD_LINK_ID;

            //TODO: Above order - first getting interface, then changing the mld_enable/enabled values
            //seems weird but it is important, as wifi_hal_get_first_mld_interface due to its structure
            //may return invalid value in some cases. Also, Currently NULL here means there was an
            //error. This function should be reworked in future.
            if (first_interface == NULL) {
                 wifi_hal_error_print("%s:%d: Failed to determine first MLD interface for %s\n",
                     __func__, __LINE__, interface->mld_name);
                 return -1;
            }

            // Reload to update MLD
            if (first_interface->u.ap.hapd.mld != NULL &&
                hostapd_mld_is_first_bss(&first_interface->u.ap.hapd)) {
                if (reload_vap_configuration(first_interface) != 0) {
                    wifi_hal_error_print(
                        "%s:%d: Failed to reload VAP configuration for MLD ID %d\n", __func__,
                        __LINE__, interface->vap_info.u.bss_info.mld_info.common_info.mld_id);
                    return -1;
                }
            }

            // If first interface does not have MLD, then MLD is gone.
            if (first_interface->u.ap.hapd.mld == NULL) {
                if (nl80211_interface_enable(interface->mld_name, false) < 0) {
                    wifi_hal_error_print("%s:%d: Failed to enable MLD interface %s\n", __func__,
                        __LINE__, interface->mld_name);
                    return -1;
                }
            }

        } else if (is_mlo_enabled == false && should_enable_mlo == true) {
            // We need to update data now since at this point vap_info is not yet copied
            interface->vap_info.u.bss_info.mld_info.common_info.mld_enable =
                vap->u.bss_info.mld_info.common_info.mld_enable;
            interface->vap_info.u.bss_info.enabled = vap->u.bss_info.enabled;

            if (setup_mlo_vap(interface, vap) != 0) {
                wifi_hal_error_print("%s:%d: Failed to setup link for MLD ID %d with VAP idx %d\n",
                    __func__, __LINE__, vap->u.bss_info.mld_info.common_info.mld_id,
                    vap->vap_index);
                return -1;
            }

            if (reload_vap_configuration(interface) != 0) {
                wifi_hal_error_print("%s:%d: Failed to reload MLD ID %d \n", __func__, __LINE__,
                    vap->u.bss_info.mld_info.common_info.mld_id);
                return -1;
            }
        }

        // Update MLD_Addr and link ID
        memcpy(vap->u.bss_info.mld_info.common_info.mld_addr,
            interface->vap_info.u.bss_info.mld_info.common_info.mld_addr, sizeof(mac_address_t));
        vap->u.bss_info.mld_info.common_info.mld_link_id =
            interface->vap_info.u.bss_info.mld_info.common_info.mld_link_id;
#endif // CONFIG_IEEE80211BE && CONFIG_GENERIC_MLO
    }
    return 0;
}
}
