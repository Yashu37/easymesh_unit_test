/*
 * HANDLER: wifi_hal_init (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:411-581 (~/Desktop/G/rdk-wifi-hal), preprocessor branches included: with no platform macro defined the generic
 * branch is the one compiled (no CONFIG_WIFI_EMULATOR, no BANANA_PI, no CONFIG_HW_CAPABILITIES).  This file holds the ORIGINAL code: no fix is applied.
 * It waits for the driver module, initialises the locks and the netlink socket map, brings up nl80211 / the primary interfaces / the radio info / eloop, starts the netlink
 * receive thread, registers the EAP methods, updates the hostapd interfaces of every present radio, the channel flags, and runs the platform radio-caps and flags hooks.
 *
 * Scaffolding only (every helper is a stub that appends a token to a call trace and returns the runner's value): get_wifi_drv_name, lsmod_by_name (answers false N times
 * first), hash_map_create, init_nl80211, create_ecomode_interfaces, nl80211_init_primary_interfaces, nl80211_init_radio_info, eloop_init, eap_server_register_methods,
 * get_radio_by_rdk_index (the real loop over g_wifi_hal.radio_info), update_hostap_interfaces, update_channel_flags, the two platform hook getters, pthread_create (no thread is
 * started), close (records the fd instead of closing it) and usleep (no sleep); the print macros map to hwr_print.  Renamed hwr_sg_wifi_hal_init.
 */
#include "hwr_whi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define wifi_hal_error_print(format, ...)  hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_info_print(format, ...)   hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define INT int
#define RETURN_OK 0
#define RETURN_ERR -1
#define HOSTAPD_VERSION 210
typedef struct wifi_interface_info_t wifi_interface_info_t;
typedef int (*platform_get_radio_caps_t)(unsigned int index);
typedef int (*platform_flags_init_t)(int *flags);
#define wifi_radio_info_t hwr_whi_radio_t
#define g_wifi_hal hwr_whi_world.hal
#define wifi_hal_init hwr_sg_wifi_hal_init
#define pthread_create hwr_whi_pthread_create
#define close hwr_whi_close
#define usleep hwr_whi_usleep
#define get_wifi_drv_name hwr_whi_get_wifi_drv_name
#define lsmod_by_name hwr_whi_lsmod_by_name
#define hash_map_create hwr_whi_hash_map_create
#define init_nl80211 hwr_whi_init_nl80211
#define create_ecomode_interfaces hwr_whi_create_ecomode_interfaces
#define nl80211_init_primary_interfaces hwr_whi_nl80211_init_primary_interfaces
#define nl80211_init_radio_info hwr_whi_nl80211_init_radio_info
#define eloop_init hwr_whi_eloop_init
#define nl_recv_func hwr_whi_nl_recv_func
#define eap_server_register_methods hwr_whi_eap_server_register_methods
#define get_radio_by_rdk_index hwr_whi_get_radio_by_rdk_index
#define update_hostap_interfaces hwr_whi_update_hostap_interfaces
#define update_channel_flags hwr_whi_update_channel_flags
#define get_platform_get_radio_caps_fn hwr_whi_get_platform_get_radio_caps_fn
#define get_platform_flags_init_fn hwr_whi_get_platform_flags_init_fn

hwr_whi_world_t hwr_whi_world;

static void tr(const char *s) { size_t n = strlen(hwr_whi_world.trace); snprintf(hwr_whi_world.trace + n, sizeof(hwr_whi_world.trace) - n, "%s ", s); }
static void tri(const char *s, int i) { char b[32]; snprintf(b, sizeof(b), "%s%d", s, i); tr(b); }

extern "C" {
char *hwr_whi_get_wifi_drv_name() { tr("D"); return hwr_whi_world.drv_null ? NULL : (char *)"mt7915e"; }
bool hwr_whi_lsmod_by_name(const char *name) { tr("L"); return hwr_whi_world.lsmod_calls++ >= hwr_whi_world.lsmod_false; }
void *hwr_whi_hash_map_create() { tr("M"); return (void *)&hwr_whi_world.lsmod_calls; }
int hwr_whi_init_nl80211() { tr("I"); return hwr_whi_world.init_ret; }
int hwr_whi_create_ecomode_interfaces(void) { tr("E"); return hwr_whi_world.eco_ret; }
int hwr_whi_nl80211_init_primary_interfaces() { tr("P"); return hwr_whi_world.prim_ret; }
int hwr_whi_nl80211_init_radio_info() { tr("R"); return hwr_whi_world.rinfo_ret; }
int hwr_whi_eloop_init() { tr("O"); return hwr_whi_world.eloop_ret; }
void *hwr_whi_nl_recv_func(void *arg) { return NULL; }
int hwr_whi_pthread_create(pthread_t *t, const pthread_attr_t *a, void *(*fn)(void *), void *arg) { tr("T"); return hwr_whi_world.pthr_ret; }
int hwr_whi_close(int fd) { tri("C", fd); return 0; }
int hwr_whi_usleep(unsigned int us) { return 0; }
int hwr_whi_eap_server_register_methods() { tr("A"); return hwr_whi_world.eap_ret; }
hwr_whi_radio_t *hwr_whi_get_radio_by_rdk_index(unsigned int index)
{
    for (unsigned int i = 0; i < g_wifi_hal.num_radios; i++)
        if (g_wifi_hal.radio_info[i].rdk_radio_index == index) return &g_wifi_hal.radio_info[i];
    return NULL;
}
int hwr_whi_update_hostap_interfaces(hwr_whi_radio_t *radio) { tri("U", radio->index); return (int)radio->index == hwr_whi_world.upd_fail_radio ? -1 : 0; }
int hwr_whi_update_channel_flags() { tr("F"); return hwr_whi_world.chan_ret; }
static int whi_caps(unsigned int index) { tri("G", index); return 0; }
static int whi_flags(int *flags) { tr("S"); *flags = 0x1f; return 0; }
platform_get_radio_caps_t hwr_whi_get_platform_get_radio_caps_fn() { return hwr_whi_world.caps_fn ? whi_caps : NULL; }
platform_flags_init_t hwr_whi_get_platform_flags_init_fn() { return hwr_whi_world.flags_fn ? whi_flags : NULL; }

/* --- wifi_hal.c:411-581 --- */
INT wifi_hal_init()
{
#ifndef CONFIG_WIFI_EMULATOR
    unsigned int i;
    wifi_radio_info_t *radio;
    platform_get_radio_caps_t get_radio_caps_fn;
    platform_flags_init_t flags_init_fn;
#endif
    pthread_attr_t *attrp = NULL;
#if defined(_PLATFORM_BANANAPI_R4_)
    ssize_t stack_size = 0x800000; /* 8MB */
    pthread_attr_t attr;
    int ret = 0;
#endif
    char *drv_name;

    wifi_hal_info_print("%s:%d: start\n", __func__, __LINE__);
#if defined(BANANA_PI_PORT) && (HOSTAPD_VERSION >= 211) && defined(CONFIG_WIFI_EMULATOR_EXT_AGENT)
    void supplicant_event(void *ctx, enum wpa_event_type event, union wpa_event_data *data);
    wpa_supplicant_event = supplicant_event;
#elif defined(BANANA_PI_PORT) && (HOSTAPD_VERSION >= 211)
    void hostapd_wpa_event(void *ctx, enum wpa_event_type event, union wpa_event_data *data);
    wpa_supplicant_event = hostapd_wpa_event;
#endif // BANANA_PI_PORT
    if ((drv_name = get_wifi_drv_name()) == NULL) {
        wifi_hal_error_print("%s:%d: driver not found, get drv name failed\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    /* check if driver is loaded */
    while (lsmod_by_name(drv_name) == false) {
        usleep(5000);
    }

    pthread_mutexattr_init(&g_wifi_hal.hapd_lock_attr);
    pthread_mutexattr_settype(&g_wifi_hal.hapd_lock_attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&g_wifi_hal.hapd_lock, &g_wifi_hal.hapd_lock_attr);

    pthread_mutex_init(&g_wifi_hal.nl_create_socket_lock, NULL);
    pthread_mutex_init(&g_wifi_hal.steering_data_lock, NULL);
    g_wifi_hal.netlink_socket_map = hash_map_create();

    if (init_nl80211() != 0) {
        return RETURN_ERR;
    }
#ifndef CONFIG_WIFI_EMULATOR
    if (create_ecomode_interfaces() != 0) {
        wifi_hal_error_print("%s:%d: Failed to create the ECO mode interfaces\n", __func__, __LINE__);
    }

#ifndef CONFIG_WIFI_EMULATOR_EXT_AGENT
    if (nl80211_init_primary_interfaces() != 0) {
        return RETURN_ERR;
    }
#endif //CONFIG_WIFI_EMULATOR_EXT_AGENT

    if (nl80211_init_radio_info() != 0) {
        return RETURN_ERR;
    }
#endif
    if (eloop_init() < 0) {
        wifi_hal_error_print("%s:%d: Failed to setup eloop\n", __func__, __LINE__);
        close(g_wifi_hal.nl_event_fd);
        return RETURN_ERR;
    }

#if defined(_PLATFORM_BANANAPI_R4_)
    attrp = &attr;
    pthread_attr_init(&attr);
    ret = pthread_attr_setstacksize(&attr, stack_size);
    if (ret != 0) {
        wifi_hal_error_print("%s:%d pthread_attr_setstacksize failed for size:%ld ret:%d\n",
            __func__, __LINE__, stack_size, ret);
    }
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
#endif
    if (pthread_create(&g_wifi_hal.nl_tid, attrp, nl_recv_func, &g_wifi_hal) != 0) {
        wifi_hal_error_print("%s:%d:ssp_main create failed\n", __func__, __LINE__);
#if defined(_PLATFORM_BANANAPI_R4_)
        if (attrp != NULL) {
            pthread_attr_destroy(attrp);
        }
#endif
        return RETURN_ERR;
    }
#if defined(_PLATFORM_BANANAPI_R4_)
    if (attrp != NULL) {
        pthread_attr_destroy(attrp);
    }
#endif
#ifndef CONFIG_WIFI_EMULATOR
    if (eap_server_register_methods() != 0) {
        wifi_hal_error_print("%s:%d: failing to register eap server default methods\n", __func__, __LINE__);
        close(g_wifi_hal.nl_event_fd);
        return RETURN_ERR;
    }

    for (i = 0; i < g_wifi_hal.num_radios; i++) {
        radio = get_radio_by_rdk_index(i);
        if (radio->radio_presence == false) {
            wifi_hal_error_print("%s:%d: Skip the Radio %d .This is sleeping in ECO mode \n", __func__, __LINE__, radio->index);
            continue;
        }
        if(update_hostap_interfaces(radio) != RETURN_OK) {
            return RETURN_ERR;
        }
    }

    if (update_channel_flags() != 0) {
        return RETURN_ERR;
    }

#if defined(CONFIG_HW_CAPABILITIES) || defined(VNTXER5_PORT) || defined(TARGET_GEMINI7_2)
    for (i = 0; i < g_wifi_hal.num_radios; i++) {
        wifi_interface_info_t *first_ap_interface = NULL;
        wifi_interface_info_t *interface;
        radio = get_radio_by_rdk_index(i);
        update_hostap_config_params(radio);
        interface = hash_map_get_first(radio->interface_map);

        while (interface != NULL) {
            if (interface->vap_info.vap_mode == wifi_vap_mode_ap && update_hostap_data(interface) == RETURN_OK) {
                update_hostap_iface(interface);
                update_hostap_iface_flags(interface);
                init_hostap_hw_features(interface);
		        if (first_ap_interface == NULL) {
                    first_ap_interface = interface;
                    wifi_hal_dbg_print("%s:%d: Saved first AP interface %s for radio %u\n",
                                       __func__, __LINE__, interface->name, i);
                }
            }
            interface = hash_map_get_next(radio->interface_map, interface);
        }
        if (first_ap_interface != NULL) {
            struct hostapd_iface *iface = &first_ap_interface->u.ap.iface;
            if (iface->num_hw_features > 0) {
                wifi_hal_dbg_print("%s:%d: Copying hw_features to radio->hw_modes for radio %u:%d\n",
                                   __func__, __LINE__, i, radio->rdk_radio_index);
                copy_hw_features_to_radio_hw_modes(radio, iface);
            } else {
                wifi_hal_dbg_print("%s:%d: No hw_features found for radio %u (num_hw_features=%u)\n",
                                   __func__, __LINE__, i, iface->num_hw_features);
            }
        } else {
            wifi_hal_dbg_print("%s:%d: No AP interface found for radio %u\n", __func__, __LINE__, i);
        }
    }
#endif // CONFIG_HW_CAPABILITIES || VNTXER5_PORT || TARGET_GEMINI7_2

    if ((get_radio_caps_fn = get_platform_get_radio_caps_fn()) != NULL) {
        wifi_hal_dbg_print("%s:%d: get platform radio capabilities\n", __func__, __LINE__);
        for (i = 0; i < g_wifi_hal.num_radios; i++) {
            get_radio_caps_fn(i);
        }
    }

    if ((flags_init_fn = get_platform_flags_init_fn()) != NULL) {
        wifi_hal_dbg_print("%s:%d: set platform specific flags\n", __func__, __LINE__);
        flags_init_fn((int *)&g_wifi_hal.platform_flags);
    }
#endif

    wifi_hal_info_print("%s:%d: HOSTAP_VERSION: %d\n", __func__, __LINE__, HOSTAPD_VERSION);

#ifdef CONFIG_WIFI_EMULATOR
    rearrange_interfaces_map();
#endif
    wifi_hal_info_print("%s:%d: done\n", __func__, __LINE__);

    return RETURN_OK;
}
}
