/*
 * HANDLER: wifi_hal_getHalCapability (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:129-378 (~/Desktop/G/rdk-wifi-hal), preprocessor branches included: with no platform macro defined the
 * generic branch is the one compiled (factory_nvram.data reads, eth0 AL mac).  This file holds the ORIGINAL code with fixes 1-3 applied
 * (start fix n / end fix n markers; the unfixed copy is the reproducer).
 * It fills the capability structure from shell command output (serial, model, image version, CM mac), the AL mac / colocated mode from EM_CFG_FILE and, per radio,
 * the radio presence, the interface firmware version and the radio capabilities.  The shell output is copied with strcpy into 64-byte fields and the radio loop
 * trusts g_wifi_hal.num_radios and get_radio_by_rdk_index().
 *
 * Scaffolding only (src/ helpers stubbed over runner-owned data, same behaviour as the real ones): _syscmd (canned reply chosen by the command text),
 * access (EASYMESH_OFF_FLAG), json_parse_string / json_parse_integer, get_mac_address, get_ifname_from_mac, configure_vap_name_basedon_colocated_mode,
 * to_mac_bytes / to_mac_str, get_radio_by_rdk_index (the real loop over g_wifi_hal.radio_info), hash_map_get_first / get_next, get_band_info_from_rdk_radio_index,
 * adjust_radio_capability_band, get_wifi_interface_info_map / get_radio_interface_info_map (copy of the real ones: empty here); print macros map to hwr_print.
 * Renamed hwr_sg_wifi_hal_getHalCapability.
 */
#include "hwr_ghc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#define wifi_hal_error_print(format, ...)  hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_info_print(format, ...)   hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define INT int
#define RETURN_OK 0
#define RETURN_ERR -1
#define WIFI_HAL_MAJOR 3
#define WIFI_HAL_MINOR 0
#define BSS_MAX_NUM_STA_COMMON 75
#define EASYMESH_OFF_FLAG "/nvram/rdkb_user_easymesh_off"
#define EM_CFG_FILE "/nvram/EasymeshCfg.json"
#define NULL_PTR_ASSERT_RC(ptr, retcode) \
    do { \
        if (NULL == ptr) { \
            wifi_hal_error_print("%s:%d NULL pointer!\n", __FUNCTION__, __LINE__); \
            return retcode; \
        } \
    } while (0)
#define NULL_PTR_ASSERT(ptr)            NULL_PTR_ASSERT_RC(ptr, WIFI_HAL_INVALID_ARGUMENTS)
#define wifi_radio_info_t hwr_ghc_radio_t
#define hash_map_t hwr_ghc_map_t
#define access hwr_ghc_access
#define wifi_hal_getHalCapability hwr_sg_wifi_hal_getHalCapability
#define g_wifi_hal hwr_ghc_world.hal
#define _syscmd hwr_ghc_syscmd
#define json_parse_string hwr_ghc_json_parse_string
#define json_parse_integer hwr_ghc_json_parse_integer
#define get_mac_address hwr_ghc_get_mac_address
#define to_mac_bytes hwr_ghc_to_mac_bytes
#define to_mac_str hwr_ghc_to_mac_str
#define get_ifname_from_mac hwr_ghc_get_ifname_from_mac
#define configure_vap_name_basedon_colocated_mode hwr_ghc_configure_vap_name_basedon_colocated_mode
#define get_radio_by_rdk_index hwr_ghc_get_radio_by_rdk_index
#define hash_map_get_first hwr_ghc_hash_map_get_first
#define hash_map_get_next hwr_ghc_hash_map_get_next
#define get_band_info_from_rdk_radio_index hwr_ghc_get_band_info_from_rdk_radio_index
#define adjust_radio_capability_band hwr_ghc_adjust_radio_capability_band
#define get_wifi_interface_info_map hwr_ghc_get_wifi_interface_info_map
#define get_radio_interface_info_map hwr_ghc_get_radio_interface_info_map

hwr_ghc_world_t hwr_ghc_world;

extern "C" {
static int hwr_ghc_access(const char *path, int mode)
{
    if (hwr_ghc_world.off_flag) return 0;
    errno = hwr_ghc_world.access_errno ? hwr_ghc_world.access_errno : ENOENT;
    return -1;
}
int _syscmd(char *cmd, char *retBuf, int retBufSize)
{
    const char *r = strstr(cmd, "Serial") ? hwr_ghc_world.serial : strstr(cmd, "MODEL") ? hwr_ghc_world.model :
        strstr(cmd, "imagename") ? hwr_ghc_world.image : strstr(cmd, "'CM'") ? hwr_ghc_world.cm : NULL;
    hwr_ghc_world.syscmd_calls++;
    if (r != NULL && retBufSize > 0) snprintf(retBuf, retBufSize, "%s", r);   /* like the real _syscmd: bounded by retBufSize */
    return 0;
}
int json_parse_string(const char *file_name, const char *item_name, char *val, size_t len)
{
    if (hwr_ghc_world.js_ret == 0 && hwr_ghc_world.js_val != NULL) snprintf(val, len, "%s", hwr_ghc_world.js_val);
    return hwr_ghc_world.js_ret;
}
int json_parse_integer(const char *file_name, const char *item_name, int *val)
{
    if (hwr_ghc_world.ji_ret == 0) *val = hwr_ghc_world.ji_val;
    return hwr_ghc_world.ji_ret;
}
int get_mac_address(char *intf_name, mac_address_t mac)
{
    if (hwr_ghc_world.eth_ret == RETURN_OK) memcpy(mac, hwr_ghc_world.eth_mac, 6);
    return hwr_ghc_world.eth_ret;
}
void to_mac_bytes(char *key, mac_address_t bmac)
{
    unsigned int v[6];
    if (sscanf(key, "%2x:%2x:%2x:%2x:%2x:%2x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) == 6)
        for (int i = 0; i < 6; i++) bmac[i] = (unsigned char)v[i];
    else memset(bmac, 0, 6);
}
char *to_mac_str(const mac_address_t mac, mac_addr_str_t key)
{
    snprintf(key, sizeof(mac_addr_str_t), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return key;
}
bool get_ifname_from_mac(const mac_address_t *mac, char *ifname)
{
    if (hwr_ghc_world.found && hwr_ghc_world.ifname != NULL) snprintf(ifname, 100, "%s", hwr_ghc_world.ifname);
    return hwr_ghc_world.found != 0;
}
int configure_vap_name_basedon_colocated_mode(char *ifname, int colocated_mode) { return hwr_ghc_world.conf_ret; }
hwr_ghc_radio_t *get_radio_by_rdk_index(unsigned int index)
{
    for (unsigned int i = 0; i < g_wifi_hal.num_radios; i++)
        if (g_wifi_hal.radio_info[i].rdk_radio_index == index) return &g_wifi_hal.radio_info[i];
    return NULL;
}
void *hash_map_get_first(hwr_ghc_map_t *map) { return map->n > 0 ? map->items[0] : NULL; }
void *hash_map_get_next(hwr_ghc_map_t *map, void *data)
{
    for (int i = 0; i + 1 < map->n; i++) if (map->items[i] == data) return map->items[i + 1];
    return NULL;
}
unsigned int get_band_info_from_rdk_radio_index(unsigned int rdk_radio_index) { hwr_ghc_world.band_calls++; return rdk_radio_index; }
int adjust_radio_capability_band(wifi_radio_capabilities_t *cap, unsigned int radio_band) { hwr_ghc_world.adjust_calls++; return 0; }
void get_wifi_interface_info_map(wifi_interface_name_idex_map_t *interface_map) { hwr_ghc_world.size_calls++; }
void get_radio_interface_info_map(radio_interface_mapping_t *radio_interface_map) { }

/* --- wifi_hal.c:129-378 --- */
INT wifi_hal_getHalCapability(wifi_hal_capability_t *hal)
{
    unsigned int i;
    wifi_interface_info_t *interface;
    wifi_radio_info_t *radio;
    wifi_radio_capabilities_t *cap;
    wifi_vap_info_t *vap;
    unsigned int radio_band = 0;
    char output[256] = {0};
    mac_addr_str_t al_ctrl_mac;
    char ifname[100] = {0};
    int ret = 0, colocated_mode;
    bool interface_found = false;
    size_t len;

    NULL_PTR_ASSERT(hal);

    hal->version.major = WIFI_HAL_MAJOR;
    hal->version.minor = WIFI_HAL_MINOR;

    hal->wifi_prop.numRadios = g_wifi_hal.num_radios;
    /* start fix 2 */
    if (hal->wifi_prop.numRadios > MAX_NUM_RADIOS) {
        wifi_hal_error_print("%s:%d: %u radios, only %d fit in the capability structure\n", __func__, __LINE__,
            hal->wifi_prop.numRadios, MAX_NUM_RADIOS);
        hal->wifi_prop.numRadios = MAX_NUM_RADIOS;
    }
    /* end fix 2 */

    /*
     * RDKB-32778: Determine max number of stations for given platform
     *
     * This is one time operation upon system bring-up. Hence, consider this routine as
     * SET operation as well because as far as RDKB perspective the driver has already
     * returned HAL capabilities but this routine tweaks HAL caps based on platform and
     * it's requirements.
     */
#if defined(_SKY_HUB_COMMON_PRODUCT_REQ_) && !defined(_SR213_PRODUCT_REQ_) && !defined(_SCER11BEL_PRODUCT_REQ_) && !defined(_SCXF11BFL_PRODUCT_REQ_)
    /* For SKY platforms, set as per _SKY macro defined */
    hal->wifi_prop.BssMaxStaAllow = BSS_MAX_NUM_STA_SKY;
#elif defined(TCXB8_PORT) || defined(XB10_PORT) || defined(SCXER10_PORT) || defined(VNTXER5_PORT) || defined(SCXF10_PORT) || defined(XER2_PORT)
    /* For TCHXB8 platforms, set as per _XB8 macro defined */
    hal->wifi_prop.BssMaxStaAllow = BSS_MAX_NUM_STA_XB8;
#else
    /* For all other platforms, set as per _COMMON macro defined. */
    hal->wifi_prop.BssMaxStaAllow = BSS_MAX_NUM_STA_COMMON;
#endif
#if !defined(_PLATFORM_RASPBERRYPI_)
    /* Copy device manufacturer,model,serial no and software version to here */
    memset(output, '\0', sizeof(output));
#if defined (_PLATFORM_BANANAPI_R4_)
    _syscmd("cat /etc/machine-id", output, sizeof(output));
    if (strlen(output) == 0) {
        strncpy(output, "bpi-123", sizeof(output));
    }
#else
    _syscmd("grep -a 'Serial' /tmp/factory_nvram.data | cut -d ' ' -f2", output, sizeof(output));
#endif
    len = strnlen(output, sizeof(output));
    if (len != 0 && output[len - 1] == '\n') {
        output[len - 1] = '\0';
    }
    /* start fix 1 */
    snprintf(hal->wifi_prop.serialNo, sizeof(hal->wifi_prop.serialNo), "%s", output);
    /* end fix 1 */

    memset(output, '\0', sizeof(output));
#if defined (_PLATFORM_BANANAPI_R4_)
    _syscmd("cat /proc/device-tree/model | tr -d ' '", output, sizeof(output));
    if (strlen(output) == 0) {
        strncpy(output, "Banana Pi - R4", sizeof(output));
    }
#else
    _syscmd("grep -a 'MODEL' /tmp/factory_nvram.data | cut -d ' ' -f2", output, sizeof(output));
#endif
    len = strnlen(output, sizeof(output));
    if (len != 0 && output[len - 1] == '\n') {
        output[len - 1] = '\0';
    }
    /* start fix 1 */
    snprintf(hal->wifi_prop.manufacturerModel, sizeof(hal->wifi_prop.manufacturerModel), "%s", output);
    /* end fix 1 */
    /* start fix 1 */
    snprintf(hal->wifi_prop.manufacturer, sizeof(hal->wifi_prop.manufacturer), "%s", output);
    /* end fix 1 */

    memset(output, '\0', sizeof(output));
    _syscmd("grep 'imagename:' /version.txt | cut -d ':' -f2 ", output, sizeof(output));
#if defined(_PLATFORM_BANANAPI_R4_)
    if (strlen(output) == 0) {
        strncpy(output, "Banana Pi - R4 V1.0", sizeof(output));
    }
#endif
    len = strnlen(output, sizeof(output));
    if (len != 0 && output[len - 1] == '\n') {
        output[len - 1] = '\0';
    }
    /* start fix 1 */
    snprintf(hal->wifi_prop.software_version, sizeof(hal->wifi_prop.software_version), "%s", output);
    /* end fix 1 */

    // CM mac
    memset(output, '\0', sizeof(output));
#if defined (_PLATFORM_BANANAPI_R4_)
    if (get_mac_address("erouter0", hal->wifi_prop.cm_mac) != RETURN_OK) {
       if (get_mac_address("eth0", hal->wifi_prop.cm_mac) != RETURN_OK) {
            wifi_hal_error_print("%s:%d: Unable to get CM mac address\n", __func__, __LINE__);
            memset(hal->wifi_prop.cm_mac, 0, sizeof(hal->wifi_prop.cm_mac));
       }
    }
#else
    _syscmd("grep -a 'CM' /tmp/factory_nvram.data | cut -d ' ' -f2", output, sizeof(output));
    len = strnlen(output, sizeof(output));
    if (len != 0 && output[len - 1] == '\n') {
        output[len - 1] = '\0';
    }
    to_mac_bytes(output,hal->wifi_prop.cm_mac);
#endif


    memset(output, '\0', sizeof(output));
#if defined (_PLATFORM_BANANAPI_R4_)
    if (get_mac_address("erouter0", hal->wifi_prop.al_1905_mac) != RETURN_OK) {
       if (get_mac_address("eth0", hal->wifi_prop.al_1905_mac) != RETURN_OK) {
            wifi_hal_error_print("%s:%d: Unable to get AL mac address\n", __func__, __LINE__);
            memset(hal->wifi_prop.al_1905_mac, 0, sizeof(hal->wifi_prop.al_1905_mac));
       }
    }
#else
    if (get_mac_address("eth0", hal->wifi_prop.al_1905_mac) != RETURN_OK) {
        wifi_hal_error_print("%s:%d: Unable to get AL mac address\n", __func__, __LINE__);
        memset(hal->wifi_prop.al_1905_mac, 0, sizeof(hal->wifi_prop.al_1905_mac));
    }
#endif

#elif (defined (_PLATFORM_RASPBERRYPI_))
   /* Copy device manufacturer,model,serial no and software version to here */
    memset(output, '\0', sizeof(output));
    _syscmd("grep -a 'Serial' /proc/cpuinfo | cut -d ':' -f2", output, sizeof(output));
    len = strnlen(output, sizeof(output));
    if (len != 0 && output[len - 1] == '\n') {
        output[len - 1] = '\0';
    }
    /* start fix 1 */
    snprintf(hal->wifi_prop.serialNo, sizeof(hal->wifi_prop.serialNo), "%s", output);
    /* end fix 1 */

    memset(output, '\0', sizeof(output));
    _syscmd("grep -a 'Model' /proc/cpuinfo | cut -d ':' -f2", output, sizeof(output));
    len = strnlen(output, sizeof(output));
    if (len != 0 && output[len - 1] == '\n') {
        output[len - 1] = '\0';
    }
    /* start fix 1 */
    snprintf(hal->wifi_prop.manufacturerModel, sizeof(hal->wifi_prop.manufacturerModel), "%s", output);
    /* end fix 1 */
    /* start fix 1 */
    snprintf(hal->wifi_prop.manufacturer, sizeof(hal->wifi_prop.manufacturer), "%s", output);
    /* end fix 1 */

    memset(output, '\0', sizeof(output));
    _syscmd("vcgencmd version | grep 'version' | cut -d ' ' -f2", output, sizeof(output));
    len = strnlen(output, sizeof(output));
    if (len != 0 && output[len - 1] == '\n') {
        output[len - 1] = '\0';
    }
    /* start fix 1 */
    snprintf(hal->wifi_prop.software_version, sizeof(hal->wifi_prop.software_version), "%s", output);
    /* end fix 1 */

    // CM mac
    memset(output, '\0', sizeof(output));
    if (get_mac_address("eth0", hal->wifi_prop.cm_mac) != RETURN_OK) {
        wifi_hal_error_print("%s:%d: Unable to get CM mac address\n", __func__, __LINE__);
        memset(hal->wifi_prop.cm_mac, 0, sizeof(hal->wifi_prop.cm_mac));
    }

    memset(output, '\0', sizeof(output));
    if (get_mac_address("eth0", hal->wifi_prop.al_1905_mac) != RETURN_OK) {
        wifi_hal_error_print("%s:%d: Unable to get AL mac address\n", __func__, __LINE__);
        memset(hal->wifi_prop.al_1905_mac, 0, sizeof(hal->wifi_prop.al_1905_mac));
    }
#endif

    if (access(EASYMESH_OFF_FLAG, F_OK) == 0) {
        hal->wifi_prop.colocated_mode = -1;
        wifi_hal_info_print("%s:%d: %s file exists, easymesh is disabled\n", __func__, __LINE__, EASYMESH_OFF_FLAG);
    } else {
        if (errno != ENOENT) {
            wifi_hal_error_print("%s:%d: access(%s) failed: %s\n", __func__, __LINE__, EASYMESH_OFF_FLAG, strerror(errno));
        }
    /* Read the al_mac address from EM_CFG_FILE */
    ret = json_parse_string(EM_CFG_FILE, "Al_MAC_ADDR", al_ctrl_mac, sizeof(al_ctrl_mac));
    if (ret == 0) {
        to_mac_bytes(al_ctrl_mac, hal->wifi_prop.al_1905_mac);
        wifi_hal_dbg_print("%s:%d al_mac %s read from json file:%s.\n", __func__, __LINE__,
            al_ctrl_mac, EM_CFG_FILE);
    } else {
        wifi_hal_error_print("%s:%d: Unable to read al_mac from json file:%s, error:%d\n", __func__,
            __LINE__, EM_CFG_FILE, ret);
        memset(hal->wifi_prop.al_1905_mac, 0, sizeof(hal->wifi_prop.al_1905_mac));
        hal->wifi_prop.colocated_mode = -1;
    }

    /* Read the collocated mode from EM_CFG_FILE*/
    ret = json_parse_integer(EM_CFG_FILE, "Colocated_Mode", &colocated_mode);
    if (ret == 0) {
        hal->wifi_prop.colocated_mode = colocated_mode;
        interface_found = get_ifname_from_mac((mac_address_t *)hal->wifi_prop.al_1905_mac, ifname);
        /* Based on the value of colocated_mode and the interface obtained from almac_address
           Configure the vap_name appropriately */
        if (interface_found == true) {
            if (strncmp(ifname, "eth", strlen("eth")) != 0 &&
                strncmp(ifname, "lo", strlen("lo")) != 0 &&
                strncmp(ifname, "lan", strlen("lan")) != 0 &&
                strncmp(ifname, "brlan", strlen("brlan")) != 0) {
                /* interface is not an ethernet and not an loopback interface */
                if (configure_vap_name_basedon_colocated_mode(ifname,
                        hal->wifi_prop.colocated_mode) != 0) {
                    wifi_hal_error_print(
                        "%s:%d Error configuring vapname for interface:%s, colocated_mode:%d",
                        __func__, __LINE__, ifname, hal->wifi_prop.colocated_mode);
                    hal->wifi_prop.colocated_mode = -1;
                }
            } else {
                /* almac_address is either ethernet or loopback, nothing to be done*/
            }
        } else {
            /* al_mac address configured is incorrect, reset the al_1905_mac to 0*/
            wifi_hal_error_print("%s:%d: No interface found for al_mac address:%s\n", __func__,
                __LINE__, to_mac_str(hal->wifi_prop.al_1905_mac, al_ctrl_mac));
            memset(hal->wifi_prop.al_1905_mac, 0, sizeof(hal->wifi_prop.al_1905_mac));
            hal->wifi_prop.colocated_mode = -1;
        }
    } else {
        wifi_hal_error_print("%s:%d: Unable to read colocated_mode from json file:%s, error:%d\n",
            __func__, __LINE__, EM_CFG_FILE, ret);
        hal->wifi_prop.colocated_mode = -1;
    }
    } /* EASYMESH_OFF_FLAG not present */

    wifi_hal_info_print("%s:%d: serialNo=%s, ModelName=%s,sw_version=%s, manufacturer=%s "
                        "al_mac_addr=%s colocated_mode:%d\n",
        __func__, __LINE__, hal->wifi_prop.serialNo, hal->wifi_prop.manufacturerModel,
        hal->wifi_prop.software_version, hal->wifi_prop.manufacturer,
        to_mac_str(hal->wifi_prop.al_1905_mac, al_ctrl_mac), hal->wifi_prop.colocated_mode);

    for (i = 0; i < hal->wifi_prop.numRadios; i++) {
        radio_band = 0;
        radio = get_radio_by_rdk_index(i);
        /* start fix 3 */
        if (radio == NULL) {
            wifi_hal_error_print("%s:%d: No radio with RDK radio index %d\n", __func__, __LINE__, i);
            continue;
        }
        /* end fix 3 */
        wifi_hal_info_print("%s:%d:Enumerating interfaces on PHY radio index: %d, RDK radio index:%d\n", __func__, __LINE__, radio->index, i);
        hal->wifi_prop.radio_presence[i] = radio->radio_presence;
        interface = hash_map_get_first(radio->interface_map);
        while (interface != NULL) {
            vap = &interface->vap_info;
            strncpy(interface->firmware_version, hal->wifi_prop.software_version, sizeof(interface->firmware_version) - 1);
            interface->firmware_version[sizeof(interface->firmware_version) - 1] = '\0';
            wifi_hal_info_print("%s:%d:interface name: %s, interface->firmware_version: %s, vap index: %d, vap name: %s\n", __func__, __LINE__,
                    interface->name, interface->firmware_version, vap->vap_index, vap->vap_name);
            interface = hash_map_get_next(radio->interface_map, interface);
        }

        radio_band = get_band_info_from_rdk_radio_index(i);
        cap = &hal->wifi_prop.radiocap[i];
        memcpy((unsigned char *)cap, (unsigned char *)&radio->capab, sizeof(wifi_radio_capabilities_t));
        adjust_radio_capability_band(cap, radio_band);
    }

    get_wifi_interface_info_map(hal->wifi_prop.interface_map);
    get_radio_interface_info_map(hal->wifi_prop.radio_interface_map);

    return RETURN_OK;
}
}
