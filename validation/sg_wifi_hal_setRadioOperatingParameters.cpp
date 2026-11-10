/*
 * HANDLER: wifi_hal_setRadioOperatingParameters (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:720-1129 (~/Desktop/G/rdk-wifi-hal), generic build (no CONFIG_WIFI_EMULATOR, CMXB7_PORT, BANANA_PI_PORT, CONFIG_GENERIC_MLO,
 * TCXB8/XB10/SCXER10, CONFIG_SAE or RASPBERRYPI/BANANAPI_R4 platform defines), so the preprocessor keeps exactly the code that the generic Linux target compiles.  This file holds the ORIGINAL code
 * (no fixes yet).  It validates the arguments, looks the radio up, runs the platform pre-init hook, then either toggles the radio enable state (restarting / stopping every VAP of the radio),
 * switches the channel, or pushes the full parameter set to hostapd / the driver; failed driver calls roll the radio back through the reload_config label.
 *
 * Scaffolding only: the stand-in radio / interface / hash map structures (hwr_wro.h), recording stubs for every callee (nl80211, hostapd, platform hooks), validate_radio_operation_param
 * (src/wifi_hal_rdk_util.c:326, verbatim) and a table stand-in for get_op_class_from_radio_params (channel 0 or an unknown country -> -1, else 115).  malloc / free are counted so a leak or a failed
 * allocation is visible to the runner.  The *_print macros go to the log sink hwr_print.  Renamed hwr_sg_wifi_hal_setRadioOperatingParameters.
 */
#include "hwr_wro.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

hwr_wro_world_t hwr_wro_world;

/* counted allocator (defined before malloc / free are redirected to it): a leak or a failed allocation is visible to the runner */
static void *hwr_wro_malloc(size_t n)
{
    if (hwr_wro_world.malloc_fail) return NULL;
    hwr_wro_world.live_alloc++;
    return calloc(1, n);
}
static void hwr_wro_free(void *p)
{
    if (p) hwr_wro_world.live_alloc--;
    free(p);
}

#define wifi_hal_dbg_print(format, ...)          hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_info_print(format, ...)         hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)        hwr_print(1, format, ##__VA_ARGS__)

#define g_wifi_hal hwr_wro_world.hal
#define malloc hwr_wro_malloc
#define free hwr_wro_free
#define get_op_class_from_radio_params hwr_wro_get_op_class_from_radio_params
#define validate_radio_operation_param hwr_wro_validate_radio_operation_param
#define get_radio_by_rdk_index hwr_wro_get_radio_by_rdk_index
#define get_platform_set_radio_pre_init_fn hwr_wro_get_platform_set_radio_pre_init_fn
#define get_platform_set_radio_fn hwr_wro_get_platform_set_radio_fn
#define get_platform_dfs_set_fn hwr_wro_get_platform_dfs_set_fn
#define get_primary_interface hwr_wro_get_primary_interface
#define nl80211_interface_enable hwr_wro_nl80211_interface_enable
#define nl80211_retry_interface_enable hwr_wro_nl80211_retry_interface_enable
#define wifi_hal_get_interface_name hwr_wro_wifi_hal_get_interface_name
#define update_hostap_config_params hwr_wro_update_hostap_config_params
#define update_hostap_interface_params hwr_wro_update_hostap_interface_params
#define update_hostap_radio_param hwr_wro_update_hostap_radio_param
#define hash_map_get_first hwr_wro_hash_map_get_first
#define hash_map_get_next hwr_wro_hash_map_get_next
#define start_bss hwr_wro_start_bss
#define hostapd_reload_config hwr_wro_hostapd_reload_config
#define hostapd_config_clear_wpa_psk hwr_wro_hostapd_config_clear_wpa_psk
#define nl80211_enable_ap hwr_wro_nl80211_enable_ap
#define deinit_bss hwr_wro_deinit_bss
#define nl80211_disconnect_sta hwr_wro_nl80211_disconnect_sta
#define wifi_drv_set_operstate hwr_wro_wifi_drv_set_operstate
#define wifi_hal_setRadioTransmitPower hwr_wro_wifi_hal_setRadioTransmitPower
#define nl80211_switch_channel hwr_wro_nl80211_switch_channel
#define nl80211_set_regulatory_domain hwr_wro_nl80211_set_regulatory_domain
#define nl80211_update_wiphy hwr_wro_nl80211_update_wiphy
#define wifi_setRadioDfsAtBootUpEnable hwr_wro_wifi_setRadioDfsAtBootUpEnable
#define wifi_hal_setRadioOperatingParameters hwr_sg_wifi_hal_setRadioOperatingParameters

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

extern "C" {
/* src/wifi_hal_rdk_util.c:326-345 verbatim (CONFIG_IEEE80211BE not defined) */
int validate_radio_operation_param(wifi_radio_operationParam_t *param)
{
    switch (param->channelWidth) {
    case WIFI_CHANNELBANDWIDTH_20MHZ:
    case WIFI_CHANNELBANDWIDTH_40MHZ:
    case WIFI_CHANNELBANDWIDTH_80MHZ:
    case WIFI_CHANNELBANDWIDTH_80_80MHZ:
        break;
    case WIFI_CHANNELBANDWIDTH_160MHZ:
#ifdef CONFIG_IEEE80211BE
    case WIFI_CHANNELBANDWIDTH_320MHZ:
#endif /* CONFIG_IEEE80211BE */
        if (((param->band == WIFI_FREQUENCY_5_BAND) || (param->band == WIFI_FREQUENCY_5L_BAND) || (param->band == WIFI_FREQUENCY_5H_BAND)) && (param->DfsEnabled == false)) {
            return RETURN_ERR;
        }
        break;
    default:
        return RETURN_ERR;
    }
    return RETURN_OK;
}
int get_op_class_from_radio_params(wifi_radio_operationParam_t *param)
{
    hwr_wro_world.opclass_calls++;
    if ((unsigned)param->countryCode > (unsigned)wifi_countrycode_ZW) return -1;
    if (param->channel == 0 || param->channel > 233) return -1;
    return 115;
}
wifi_radio_info_t *get_radio_by_rdk_index(unsigned int index)
{
    if (hwr_wro_world.no_radio || index >= HWR_WRO_MAXR) return NULL;
    return &hwr_wro_world.radios[index];
}
static int pre_init_ok(wifi_radio_index_t i, wifi_radio_operationParam_t *p) { hwr_wro_world.c_pre++; return 0; }
static int pre_init_bad(wifi_radio_index_t i, wifi_radio_operationParam_t *p) { hwr_wro_world.c_pre++; return -1; }
platform_set_radio_pre_init_t get_platform_set_radio_pre_init_fn(void) { return hwr_wro_world.pre_mode == 0 ? NULL : hwr_wro_world.pre_mode == 1 ? pre_init_ok : pre_init_bad; }
static int nvram_set(wifi_radio_index_t i, wifi_radio_operationParam_t *p) { hwr_wro_world.c_nvram++; return 0; }
platform_set_radio_params_t get_platform_set_radio_fn(void) { return hwr_wro_world.nvram_fn ? nvram_set : NULL; }
static int dfs_set(wifi_radio_index_t i, wifi_radio_operationParam_t *p) { hwr_wro_world.c_dfs++; return 0; }
platform_set_dfs_t get_platform_dfs_set_fn(void) { return hwr_wro_world.dfs_fn ? dfs_set : NULL; }
wifi_interface_info_t *get_primary_interface(wifi_radio_info_t *radio)
{
    if (hwr_wro_world.no_primary || radio->interface_map == NULL || radio->interface_map->n == 0) return hwr_wro_world.no_primary ? NULL : &hwr_wro_world.ifs[0];
    return radio->interface_map->items[0];
}
int nl80211_interface_enable(const char *name, bool enable) { if (enable) hwr_wro_world.c_ifen_true++; else hwr_wro_world.c_ifen_false++; return 0; }
int nl80211_retry_interface_enable(wifi_interface_info_t *interface, bool enable) { return 0; }
char *wifi_hal_get_interface_name(wifi_interface_info_t *interface) { return interface->name; }
int update_hostap_config_params(wifi_radio_info_t *radio)
{
    hwr_wro_world.c_cfg++;
    if (hwr_wro_world.hostap_fail == 1) return -1;
    if (hwr_wro_world.hostap_fail == 2 && hwr_wro_world.c_cfg == 1) return -1;
    return 0;
}
int update_hostap_interface_params(wifi_interface_info_t *interface) { return hwr_wro_world.ifparam_fail ? -1 : 0; }
void update_hostap_radio_param(wifi_radio_info_t *radio, wifi_radio_operationParam_t *param) { hwr_wro_world.c_hradio++; }
void *hash_map_get_first(hash_map_t *map)
{
    if (map == NULL) return NULL;
    map->itr = 0;
    return map->n ? map->items[0] : NULL;
}
void *hash_map_get_next(hash_map_t *map, void *data)
{
    if (map == NULL) return NULL;
    map->itr++;
    return map->itr < map->n ? map->items[map->itr] : NULL;
}
void start_bss(wifi_interface_info_t *interface) { hwr_wro_world.c_start++; }
void hostapd_reload_config(struct hostapd_iface *iface) { hwr_wro_world.c_reload++; }
void hostapd_config_clear_wpa_psk(struct hwr_wro_wpa_psk **p) { *p = NULL; }
int nl80211_enable_ap(wifi_interface_info_t *interface, bool enable) { return 0; }
void deinit_bss(struct hostapd_data *hapd) { hwr_wro_world.c_deinit++; }
int nl80211_disconnect_sta(wifi_interface_info_t *interface) { hwr_wro_world.c_disc++; return 0; }
int wifi_drv_set_operstate(wifi_interface_info_t *interface, int state) { hwr_wro_world.c_operstate++; return 0; }
int wifi_hal_setRadioTransmitPower(wifi_radio_index_t index, unsigned int power) { hwr_wro_world.c_txpow++; hwr_wro_world.last_txpow = power; return 0; }
int nl80211_switch_channel(wifi_radio_info_t *radio) { hwr_wro_world.c_switch++; return hwr_wro_world.switch_ret; }
int nl80211_set_regulatory_domain(unsigned int cc) { hwr_wro_world.c_regdom++; hwr_wro_world.last_regdom = (int)cc; return 0; }
int nl80211_update_wiphy(wifi_radio_info_t *radio) { hwr_wro_world.c_wiphy++; return hwr_wro_world.wiphy_fail ? -1 : 0; }
int wifi_setRadioDfsAtBootUpEnable(unsigned int index, bool enable) { hwr_wro_world.c_dfsboot++; return 0; }

/* --- wifi_hal.c:720-1129 --- */
INT wifi_hal_setRadioOperatingParameters(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    wifi_radio_info_t *radio;
    int op_class;
    platform_set_radio_params_t  set_radio_params_fn;
    wifi_interface_info_t *interface = NULL;
    wifi_interface_info_t *primary_interface = NULL;
    wifi_radio_operationParam_t *old_operationParam = NULL;
    platform_set_radio_pre_init_t set_radio_pre_init_fn;
    bool is_channel_changed;
    int ret;

#ifdef CMXB7_PORT
    int dfs_start_chan = 52, dfs_end_chan = 144;
#endif

    RADIO_INDEX_ASSERT(index);
    NULL_PTR_ASSERT(operationParam);

#if defined(CONFIG_WIFI_EMULATOR) || defined(CONFIG_WIFI_EMULATOR_EXT_AGENT)
    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d:Could not find radio index:%d\n", __func__, __LINE__, index);
        return RETURN_ERR;
    }

    radio->configured = true;
    radio->oper_param.enable = true;
    memcpy((unsigned char *)&radio->oper_param, (unsigned char *)operationParam,
        sizeof(wifi_radio_operationParam_t));

    return RETURN_OK;
#endif

    if ((op_class = get_op_class_from_radio_params(operationParam)) == -1) {
        wifi_hal_error_print("%s:%d:Could not find country code for radio index:%d\n", __func__, __LINE__, index);
        return WIFI_HAL_INVALID_ARGUMENTS; // RDKB-47696: Passing invalid channel should return WIFI_HAL_INVALID_ARGUMENTS(-4)
    }

    if (validate_radio_operation_param(operationParam) != RETURN_OK) {
        wifi_hal_error_print("%s:%d:Failed to validate radio operation params for radio index: %d\n", __func__, __LINE__, index);
        return WIFI_HAL_INVALID_ARGUMENTS;
    }

    operationParam->operatingClass = op_class;

    wifi_hal_info_print("%s:%d:Index:%d Country: %d, Channel: %d, Op Class:%d\n",
        __func__, __LINE__, index, operationParam->countryCode, operationParam->channel, operationParam->operatingClass);

    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d:Could not find radio index:%d\n", __func__, __LINE__, index);
        return RETURN_ERR;
    }

    if ((set_radio_pre_init_fn = get_platform_set_radio_pre_init_fn()) != NULL) {
        if (set_radio_pre_init_fn(index, operationParam) < 0){
            wifi_hal_error_print("%s:%d: Error in setting radio pre init\n", __func__, __LINE__);
            return RETURN_ERR;
        }
    } else {
        wifi_hal_error_print("%s:%d: Unable to fetch se_radio_pre_init_fn()\n", __func__, __LINE__);
    }

    if ((false == radio->radio_presence) || (operationParam->EcoPowerDown == true)) {
        wifi_hal_error_print("%s:%d: Skip the Radio %d .This is sleeping in ECO mode \n", __func__, __LINE__, radio->index);
        return RETURN_OK;
    }

    primary_interface = get_primary_interface(radio);
    if (primary_interface == NULL) {
        wifi_hal_error_print("%s:%d: Error updating dev:%d no vprimary interface exist\n", __func__, __LINE__, radio->index);
        return RETURN_ERR;
    }

    old_operationParam = (wifi_radio_operationParam_t *)malloc(sizeof(wifi_radio_operationParam_t));
    if (old_operationParam == NULL) {
        wifi_hal_error_print("%s:%d: malloc failed\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    memcpy((unsigned char *)old_operationParam, (unsigned char *)&radio->oper_param, sizeof(wifi_radio_operationParam_t));

#if !defined(BANANA_PI_PORT) && !defined(CONFIG_GENERIC_MLO)
    nl80211_interface_enable(wifi_hal_get_interface_name(primary_interface),
        operationParam->enable);
#endif
#if defined(TCXB8_PORT) || defined(XB10_PORT) || defined(SCXER10_PORT)
    if (nl80211_set_amsdu_tid(primary_interface, operationParam->amsduTid) != RETURN_OK)
    {
        wifi_hal_error_print(
            "%s:%d:Failed to update AMSDU TID params ! AMSDU possibly out of sync \n",
            __func__, __LINE__);
        // fall-through, don't return error
    }
#endif

    if (radio->configured && radio->oper_param.enable != operationParam->enable) {
        memcpy((unsigned char *)&radio->oper_param, (unsigned char *)operationParam, sizeof(wifi_radio_operationParam_t));

        if (update_hostap_config_params(radio) != RETURN_OK ) {
            wifi_hal_error_print("%s:%d:Failed to update hostap config params\n", __func__, __LINE__);
            free(old_operationParam);
            old_operationParam = NULL;
            return RETURN_ERR;
        }

        interface = hash_map_get_first(radio->interface_map);
        if (interface == NULL ) {
            wifi_hal_error_print("%s:%d: Interface map is empty for radio\n", __func__, __LINE__);
            goto Exit;
        }

        while (interface != NULL) {
            char *interface_name = wifi_hal_get_interface_name(interface);

            if (interface->vap_info.vap_mode == wifi_vap_mode_ap) {
                wifi_hal_info_print(
                    "%s:%d: vap_index: %d interface name: %s vap_initialized: %d "
                    "bss started: %d vap enabled: %d radio configured: %d radio enabled: %d\n",
                    __func__, __LINE__, interface->vap_info.vap_index, interface_name,
                    interface->vap_initialized, interface->bss_started,
                    interface->vap_info.u.bss_info.enabled, radio->configured,
                    radio->oper_param.enable);
                if (radio->oper_param.enable && interface->vap_info.u.bss_info.enabled) {
                    if (nl80211_interface_enable(interface_name, true) != 0) {
                        ret = nl80211_retry_interface_enable(interface, true);
                        if (ret != 0) {
                            wifi_hal_error_print("%s:%d: Retry of interface enable failed:%d\n",
                                __func__, __LINE__, ret);
                        }
                    }
#if defined(BANANA_PI_PORT) && defined(CONFIG_GENERIC_MLO)
                    if (wifi_hal_is_mld_enabled(interface)) {
                        if (setup_mlo_vap(interface, &interface->vap_info) != RETURN_OK) {
                            free(old_operationParam);
                            old_operationParam = NULL;
                            return RETURN_ERR;
                        }
                    }

                    //Important side effect to this is that this will make sure we trigger the beacon twice
                    if (restart_interface(interface)) {
                            free(old_operationParam);
                            old_operationParam = NULL;
                            return RETURN_ERR;
                    }

                    if (nl80211_create_bridge(interface_name, interface->vap_info.bridge_name) != 0) {
                        wifi_hal_error_print("%s:%d: Failed add interface %s to bridge %s\n",
                            __func__, __LINE__, interface_name, interface->vap_info.bridge_name);
                        free(old_operationParam);
                        old_operationParam = NULL;
                        return RETURN_ERR;
                    }

#else
                    if (update_hostap_interface_params(interface) != RETURN_OK) {
                        free(old_operationParam);
                        old_operationParam = NULL;
                        return RETURN_ERR;
                    }
#endif // defined(BANANA_PI_PORT) && defined(CONFIG_GENERIC_MLO)
                    interface->beacon_set = 0;
                    start_bss(interface);
                    interface->bss_started = true;
                }

                if (radio->oper_param.enable == false && interface->bss_started) {
#if defined(BANANA_PI_PORT) && defined(CONFIG_GENERIC_MLO)
                    if (wifi_hal_is_mld_enabled(interface)) {
                        if (teardown_mlo_vap(interface)) {
                            free(old_operationParam);
                            old_operationParam = NULL;
                            return RETURN_ERR;
                        }
                    }

                    if (reload_interface(interface)) {
                        free(old_operationParam);
                        old_operationParam = NULL;
                        return RETURN_ERR;
                    }
#else
                    /* Clear beacon interval in wdev by stoping AP */
                    nl80211_interface_enable(interface_name, false);
                    nl80211_interface_enable(interface_name, true);
                    interface->beacon_set = 0;
                    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
                    hostapd_reload_config(interface->u.ap.hapd.iface);
#ifdef CONFIG_SAE
                    if (interface->u.ap.conf.sae_groups) {
                        interface->u.ap.conf.sae_groups = NULL;
                    }
#endif
                    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
                    nl80211_enable_ap(interface, false);
                    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
                    deinit_bss(&interface->u.ap.hapd);
                    if (interface->u.ap.hapd.conf->ssid.wpa_psk && !interface->u.ap.hapd.conf->ssid.wpa_psk->next)
                        hostapd_config_clear_wpa_psk(&interface->u.ap.hapd.conf->ssid.wpa_psk);
                    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

                    if (update_hostap_interface_params(interface) != RETURN_OK) {
                        free(old_operationParam);
                        old_operationParam = NULL;
                        return RETURN_ERR;
                    }
                    interface->bss_started = false;
                    nl80211_interface_enable(interface_name, false);
#endif // BANANA_PI_PORT && CONFIG_GENERIC_MLO
                }
            }
            if (interface->vap_info.vap_mode == wifi_vap_mode_sta) {
                if (radio->oper_param.enable == false) {
                    if (interface->u.sta.state == WPA_COMPLETED) {
                        nl80211_disconnect_sta(interface);
                    }
                    nl80211_interface_enable(interface_name, false);
                }

                if (radio->oper_param.enable) {
                    nl80211_interface_enable(interface_name, true);
                    wifi_drv_set_operstate(interface, 1);
                }
            }

            interface = hash_map_get_next(radio->interface_map, interface);
        }

        goto Exit;
    }

#ifdef CMXB7_PORT
    if( primary_interface->u.ap.iface.cac_started && ((operationParam->channel >= dfs_start_chan) && (operationParam->channel <= dfs_end_chan)) && (radio->oper_param.channel == operationParam->channel) &&
      ( radio->oper_param.channelWidth == operationParam->channelWidth ) ) {
        wifi_hal_info_print("%s:%d: Setting  primary interface with channel:%u \n", __func__, __LINE__, radio->oper_param.channel);

        if (memcmp((unsigned char *)&radio->oper_param, (unsigned char *)operationParam, sizeof(wifi_radio_operationParam_t)) != 0) {
            wifi_hal_error_print("%s:%d: CAC is running for DFS Channel:%u. Wait for CAC to be over \n", __func__, __LINE__, operationParam->channel);
            free(old_operationParam);
            old_operationParam = NULL;
            return RETURN_ERR;
        }

        if( set_freq_and_interface_enable(primary_interface, radio) ) {
            goto reload_config;
        }
        goto Exit;
    }
#endif

    if (radio->oper_param.DfsEnabled != operationParam->DfsEnabled) {
        platform_set_dfs_t platform_set_dfs_fn = get_platform_dfs_set_fn();

        if (platform_set_dfs_fn != NULL) {
            platform_set_dfs_fn(index, operationParam);
        }
    }

    is_channel_changed = radio->oper_param.channel != operationParam->channel ||
        radio->oper_param.channelWidth != operationParam->channelWidth;
    if (radio->configured && radio->oper_param.enable && is_channel_changed) {
        radio->oper_param.channel = operationParam->channel;
        radio->oper_param.operatingClass = operationParam->operatingClass;
        radio->oper_param.channelWidth = operationParam->channelWidth;
        radio->oper_param.autoChannelEnabled = operationParam->autoChannelEnabled;
        if (old_operationParam->transmitPower != operationParam->transmitPower) {
            wifi_hal_info_print("%s:%d: OldTransmitPower:%d, NewTransmitPower:%d updating\n", __func__, __LINE__, old_operationParam->transmitPower, operationParam->transmitPower);
            (void)wifi_hal_setRadioTransmitPower(index, operationParam->transmitPower);
        }
        radio->oper_param.transmitPower = operationParam->transmitPower;
		radio->oper_param.DfsEnabledBootup = operationParam->DfsEnabledBootup;
		strncpy(radio->oper_param.radarDetected, operationParam->radarDetected,
				sizeof(radio->oper_param.radarDetected)-1);
		radio->oper_param.DFSTimer = operationParam->DFSTimer;
        memcpy(radio->oper_param.channel_map, operationParam->channel_map,
            sizeof(radio->oper_param.channel_map));

#ifdef CMXB7_PORT
        if( ((radio->oper_param.band == WIFI_FREQUENCY_5_BAND) || (radio->oper_param.band == WIFI_FREQUENCY_5L_BAND) || (radio->oper_param.band == WIFI_FREQUENCY_5H_BAND))) {
            if( !primary_interface->u.ap.iface.cac_started && ((operationParam->channel >= dfs_start_chan && operationParam->channel <= dfs_end_chan) || (operationParam->channelWidth == WIFI_CHANNELBANDWIDTH_160MHZ)) ) {
                wifi_hal_info_print("%s:%d: Starting CAC for DFS Channel:%u \n", __func__, __LINE__, operationParam->channel );
                if(nl80211_start_dfs_cac(radio)) {
                    wifi_hal_error_print("%s:%d: Error starting CAC \n", __func__, __LINE__);
                    goto reload_config;
                }
               goto Exit;
            }

            if( primary_interface->u.ap.iface.cac_started ) {
                int cac_start = 0;
                pthread_mutex_lock(&g_wifi_hal.hapd_lock);
                primary_interface->u.ap.iface.cac_started = cac_start;
                pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

                if(primary_interface->u.ap.iface.dfs_cac_ms)
                    reenable_prim_interface(radio);

                if( !(operationParam->channel >= dfs_start_chan && operationParam->channel <= dfs_end_chan) && !(operationParam->channelWidth == WIFI_CHANNELBANDWIDTH_160MHZ) ) {
                    wifi_hal_info_print("%s:%d: Setting channel:%u on 5GHz Radio\n", __func__, __LINE__, radio->oper_param.channel);
                    if( set_freq_and_interface_enable(primary_interface, radio) ) {
                        goto reload_config;
                    }
                    goto Exit;
                }

                wifi_hal_info_print("%s:%d: Starting CAC for DFS Channel:%u \n", __func__, __LINE__, operationParam->channel );
                if(nl80211_start_dfs_cac(radio)) {
                    wifi_hal_error_print("%s:%d: Error starting CAC \n", __func__, __LINE__);
                    goto reload_config;
                }
                goto Exit;
            }
        }
#endif
        if (memcmp((unsigned char *)&radio->oper_param, (unsigned char *)operationParam, sizeof(wifi_radio_operationParam_t)) == 0) {
            if (is_channel_changed) {
                wifi_hal_dbg_print("%s:%d: Switch channel on radio index:%d\n", __func__, __LINE__,
                    index);
                if ((ret = nl80211_switch_channel(radio)) == -1) {
                    wifi_hal_error_print("%s:%d: Error switching channel\n", __func__, __LINE__);
                    goto reload_config;
                } else if (ret != 0) {
                    wifi_hal_error_print("%s:%d: Error switching channel ret:%d\n", __func__,
                        __LINE__, ret);
                    if (ret == -EOPNOTSUPP) {
                        wifi_hal_dbg_print(
                            "%s:%d Try updation of hostap config params for EOPNOTSUPP error\n",
                            __func__, __LINE__);
                        goto try_hostap_config_update;
                    } else {
                        free(old_operationParam);
                        old_operationParam = NULL;
                        return RETURN_ERR;
                    }
                }
            }
            goto Exit;
        }
    }

try_hostap_config_update:
    if (radio->configured && is_channel_changed) {
        radio->configuration_in_progress = true;
    }
    if (radio->configured && radio->oper_param.enable) {
        update_hostap_radio_param(radio, operationParam);
    }

    if (radio->oper_param.countryCode != operationParam->countryCode) {
        wifi_hal_dbg_print("%s:%d:Set country code:%d\n", __func__, __LINE__, operationParam->countryCode);
        nl80211_set_regulatory_domain(operationParam->countryCode);
    }

    memcpy((unsigned char *)&radio->oper_param, (unsigned char *)operationParam, sizeof(wifi_radio_operationParam_t));
    // update the hostap_config parameters
    if (update_hostap_config_params(radio) != RETURN_OK ) {
        wifi_hal_error_print("%s:%d:Failed to update hostap config params\n", __func__, __LINE__);
        goto reload_config;
    }

    if (nl80211_update_wiphy(radio) != 0) {
        wifi_hal_error_print("%s:%d:Failed to update radio\n", __func__, __LINE__);
        goto reload_config;
    }

#if !defined(_PLATFORM_RASPBERRYPI_) && !defined(_PLATFORM_BANANAPI_R4_)
    // Call Vendor HAL
    if (wifi_setRadioDfsAtBootUpEnable(index,operationParam->DfsEnabledBootup) != 0) {
        wifi_hal_dbg_print("%s:%d:Failed to Enable DFSAtBootUp on radio %d\n", __func__, __LINE__, index);
    }
#endif // PLATFORM_RASPBERRYPI_ || _PLATFORM_BANANAPI_R4_

Exit:
    if ((set_radio_params_fn = get_platform_set_radio_fn()) != NULL) {
        wifi_hal_info_print("%s:%d: set radio params to nvram for radio : %d\n", __func__, __LINE__, index);
        set_radio_params_fn(index, operationParam);
    }

    if (!radio->configured) {
        radio->configured = true;
    }

    free(old_operationParam);
    old_operationParam = NULL;
    radio->configuration_in_progress = false;
    return RETURN_OK;

reload_config:
    if (radio->configured == true) {
        memcpy((unsigned char *)&radio->oper_param, (unsigned char *)old_operationParam, sizeof(wifi_radio_operationParam_t));
    }
    free(old_operationParam);
    old_operationParam = NULL;
    if (update_hostap_config_params(radio) != RETURN_OK ) {
        wifi_hal_error_print("%s:%d:Failed to update hostap config params, Got into a bad state radioindex : %d\n", __func__, __LINE__, index);
        radio->configuration_in_progress = false;
        return RETURN_ERR;
    }

    if (nl80211_update_wiphy(radio) != 0) {
        wifi_hal_error_print("%s:%d:Failed to update radio : %d\n", __func__, __LINE__, index);
        radio->configuration_in_progress = false;
        return RETURN_ERR;
    }

    radio->configuration_in_progress = false;
    return RETURN_ERR;

}
}
