/*
 * HANDLER: wifi_hal_wps_init (src/wifi_hal_hostapd.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal_hostapd.c:1019-1090 (~/Desktop/G/rdk-wifi-hal; static, compiled under CONFIG_WPS).  This file holds the ORIGINAL code (no fixes) for the function;
 * its callees wifi_hal_is_wps_enabled (#277) and wifi_hal_band_to_wps_band (#276) carry the fixes found in their own harnesses.  It resets the BSS config WPS state / RF bands, returns when WPS is not enabled
 * for the VAP or its type prefix (name up to the last '_') cannot be derived, then marks WPS configured, ORs in the WPS band of every radio that has an interface of the same type, generates the UUID from
 * the first such interface when it is nil, sets the config methods string from the onboarding methods, copies the PIN and sets credential processing / pbc_in_m1.
 *
 * Scaffolding only: stand-in types (hwr_wwi.h); WPS constants as in hostap / wifi_hal_priv.h; print macros are no-ops; sha1_vector is built on OpenSSL SHA1; the callees below are verbatim copies
 * (wifi_hal_nl80211_utils.c:2113 / 2134 / 2271, hostap utils/uuid.c:65, wps/wps_common.c:527, wifi_hal_hostapd.c:989 / 1012); renamed hwr_sg_wifi_hal_wps_init.
 */
#include "hwr_wwi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WPS_RF_24GHZ 0x01
#define WPS_RF_50GHZ 0x02
#define WPS_RF_60GHZ 0x04
#define WPS_STATE_CONFIGURED 2
#define WPS_METHODS_SIZE 512
#define WPS_PIN_SIZE     9
#define UUID_LEN 16
#define SHA1_MAC_LEN 20
#define os_memcpy memcpy
#define hash_map_get_first(map) ((map)->first)
#define hash_map_get_next(map, p) ((p)->next)
#define hash_map_foreach(map, p) \
    for (p = hash_map_get_first(map); p != NULL; p = hash_map_get_next(map, p))
static void hwr_wwi_dbg(const char *format, ...) { }
#define wifi_hal_error_print hwr_wwi_dbg
#define wifi_hal_info_print hwr_wwi_dbg
hwr_wwi_hal_t hwr_wwi_hal;
#define g_wifi_hal hwr_wwi_hal
typedef unsigned int wifi_radio_index_t;

static int sha1_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
	SHA_CTX c;
	SHA1_Init(&c);
	for (size_t i = 0; i < num_elem; i++) SHA1_Update(&c, addr[i], len[i]);
	SHA1_Final(mac, &c);
	return 0;
}

/* --- wifi_hal_nl80211_utils.c:2271 (verbatim, support code) --- */
#define get_radio_by_rdk_index hwr_wwi_get_radio_by_rdk_index
wifi_radio_info_t *get_radio_by_rdk_index(wifi_radio_index_t index)
{
    wifi_radio_info_t *radio;
    unsigned int i;

    for (i = 0; i < g_wifi_hal.num_radios; i++) {
        radio = &g_wifi_hal.radio_info[i];
        if (radio->rdk_radio_index == index) {
            return radio;
        }
    }
    return NULL;
}

/* --- wifi_hal_nl80211_utils.c:2113 (verbatim, support code) --- */
#define wifi_hal_get_vap_interface_type hwr_wwi_get_vap_interface_type
int wifi_hal_get_vap_interface_type(wifi_vap_name_t vap_name, wifi_vap_type_t vap_type)
{
    char *last_underscore;
    int len;

    if (vap_name == NULL) {
        return -1;
    }

    last_underscore = strrchr(vap_name, '_');
    if (last_underscore == NULL) {
        return -1;
    }

    len = last_underscore - vap_name + 1;
    strncpy(vap_type, vap_name, len);
    vap_type[len] = '\0';

    return 0;
}

/* --- wifi_hal_nl80211_utils.c:2134 (verbatim, support code) --- */
#define wifi_hal_get_vap_interface_by_type hwr_wwi_get_vap_interface_by_type
wifi_interface_info_t *wifi_hal_get_vap_interface_by_type(wifi_radio_info_t *radio,
    wifi_vap_type_t vap_type)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;

    if (radio == NULL) {
        return NULL;
    }

    hash_map_foreach(radio->interface_map, interface) {
        vap = &interface->vap_info;
        if (strncmp(vap->vap_name, vap_type, strnlen(vap_type, sizeof(wifi_vap_type_t))) == 0) {
            return interface;
        }
    }

    return NULL;
}

/* --- hostap utils/uuid.c:65 (verbatim, support code) --- */
#define is_nil_uuid hwr_wwi_is_nil_uuid
int is_nil_uuid(const u8 *uuid)
{
	int i;
	for (i = 0; i < UUID_LEN; i++)
		if (uuid[i])
			return 0;
	return 1;
}

/* --- hostap wps/wps_common.c:527 (verbatim, support code) --- */
#define uuid_gen_mac_addr hwr_wwi_uuid_gen_mac_addr
void uuid_gen_mac_addr(const u8 *mac_addr, u8 *uuid)
{
	const u8 *addr[2];
	size_t len[2];
	u8 hash[SHA1_MAC_LEN];
	u8 nsid[16] = {
		0x52, 0x64, 0x80, 0xf8,
		0xc9, 0x9b,
		0x4b, 0xe5,
		0xa6, 0x55,
		0x58, 0xed, 0x5f, 0x5d, 0x60, 0x84
	};

	addr[0] = nsid;
	len[0] = sizeof(nsid);
	addr[1] = mac_addr;
	len[1] = 6;
	sha1_vector(2, addr, len, hash);
	os_memcpy(uuid, hash, 16);
}

/* --- wifi_hal_hostapd.c:989 (support code; fix of finding #276 applied: NULL wps_band) --- */
#define wifi_hal_band_to_wps_band hwr_wwi_band_to_wps_band
int wifi_hal_band_to_wps_band(wifi_freq_bands_t hal_band, u8 *wps_band)
{
    /* ---------- start fix (#276): wps_band was written through without a NULL check. */
    if (wps_band == NULL) {
        return -1;
    }
    /* ---------- end fix (#276) */

    switch (hal_band) {
    case WIFI_FREQUENCY_2_4_BAND:
        *wps_band = WPS_RF_24GHZ;
        break;
    case WIFI_FREQUENCY_5_BAND:
    case WIFI_FREQUENCY_5L_BAND:
    case WIFI_FREQUENCY_5H_BAND:
        *wps_band = WPS_RF_50GHZ;
        break;
    case WIFI_FREQUENCY_6_BAND:
        /* WPS is not supported in 6G */
        *wps_band = 0;
        break;
    default:
        wifi_hal_error_print("%s:%d Unsupported frequency band\n", __func__, __LINE__);
        return -1;
    }

    return 0;
}

/* --- wifi_hal_hostapd.c:1012 (support code; fix of finding #277 applied: NULL radio / vap / conf) --- */
#define wifi_hal_is_wps_enabled hwr_wwi_is_wps_enabled
bool wifi_hal_is_wps_enabled(wifi_radio_info_t *radio, wifi_vap_info_t *vap,
    struct hostapd_bss_config *conf)
{
    /* ---------- start fix (#277): radio, vap and conf were dereferenced without a NULL check. */
    if (radio == NULL || vap == NULL || conf == NULL) {
        return false;
    }
    /* ---------- end fix (#277) */

    return vap->u.bss_info.wps.enable && !conf->ignore_broadcast_ssid &&
        radio->oper_param.band != WIFI_FREQUENCY_6_BAND;
}

#define wifi_hal_wps_init hwr_sg_wifi_hal_wps_init

extern "C" {
/* --- wifi_hal_hostapd.c:1019-1083 (static dropped so the harness can call it) --- */
void wifi_hal_wps_init(wifi_radio_info_t *radio, wifi_vap_info_t *vap,
    struct hostapd_bss_config *conf)
{
    u8 wps_band;
    wifi_vap_type_t vap_type;
    wifi_radio_info_t *radio_iter;
    wifi_interface_info_t *interface_iter;

    conf->wps_state = 0;
    conf->wps_rf_bands = 0;

    if (!wifi_hal_is_wps_enabled(radio, vap, conf)) {
        return;
    }

    if (wifi_hal_get_vap_interface_type(vap->vap_name, vap_type) < 0) {
        wifi_hal_error_print("%s:%d failed to get vap type for %s\n", __func__, __LINE__,
            vap->vap_name);
        return;
    }

    conf->wps_state |= WPS_STATE_CONFIGURED;

    for (int i = 0; i < g_wifi_hal.num_radios; i++) {
        if ((radio_iter = get_radio_by_rdk_index(i)) == NULL) {
            continue;
        }

        if ((interface_iter = wifi_hal_get_vap_interface_by_type(radio_iter, vap_type)) == NULL) {
            continue;
        }

        if (wifi_hal_band_to_wps_band(radio_iter->oper_param.band, &wps_band) < 0) {
            continue;
        }

        // Advertise all bands supported by AP
        conf->wps_rf_bands |= wps_band;

        // Use first interface UUID for all bands
        if (is_nil_uuid(conf->uuid)) {
            uuid_gen_mac_addr(interface_iter->mac, conf->uuid);
        }
    }

    if (vap->u.bss_info.wps.methods ==
        (WIFI_ONBOARDINGMETHODS_PUSHBUTTON | WIFI_ONBOARDINGMETHODS_PIN)) {
        strncpy(conf->config_methods, "label display push_button keypad", WPS_METHODS_SIZE - 1);
    } else if (vap->u.bss_info.wps.methods == WIFI_ONBOARDINGMETHODS_PUSHBUTTON) {
        strncpy(conf->config_methods,
            "display virtual_push_button physical_push_button push_button virtual_display",
            WPS_METHODS_SIZE - 1);
    } else if (vap->u.bss_info.wps.methods == WIFI_ONBOARDINGMETHODS_PIN) {
        strncpy(conf->config_methods, "keypad label display", WPS_METHODS_SIZE - 1);
    }
    wifi_hal_info_print("%s:%d Wi-Fi WPS config methods: %d\n", __func__, __LINE__,
        vap->u.bss_info.wps.methods);

    if (strlen(vap->u.bss_info.wps.pin) != 0) {
        strncpy(conf->ap_pin, vap->u.bss_info.wps.pin, WPS_PIN_SIZE - 1);
    }

    conf->wps_cred_processing = 1;
    conf->pbc_in_m1 = 1;
}
}
