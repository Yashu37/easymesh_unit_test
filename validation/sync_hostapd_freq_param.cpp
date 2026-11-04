/*
 * HANDLER: sync_hostapd_freq_param
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc_processors.c:44-72
 * (~/Desktop/G/rdk-wifi-hal).  With RDK_SHF_FIX 0 it is the VERBATIM original
 * (reproduces the findings); with RDK_SHF_FIX 1 it carries FIX 1..3 below.
 *
 * Scaffolding only (the real types need the hostap / driver header tree):
 *  - minimal wifi_interface_info_t / wifi_radio_info_t with just the fields the
 *    function touches (vap_info.radio_index, u.ap.hapd.iface->freq,
 *    oper_param.countryCode / operatingClass / channel).
 *  - get_interface_by_vap_index / get_radio_by_rdk_index: table lookups over the
 *    runner-owned slabs (NULL when not found, as in wifi_hal_nl80211_utils.c).
 *  - get_coutry_str_from_code: the real body over a reduced country map
 *    (unknown code -> "US").
 *  - ieee80211_chan_to_freq: a table with the real contract (frequency in MHz,
 *    -1 for an unknown op class / channel).
 *  - wifi_hal_*_print are the REAL macros; wifi_hal_print is the log-sink stub.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

/* 1 = with FIX 1..3, 0 = original unfixed function (set to 0 to reproduce the findings) */
#define RDK_SHF_FIX  0

#define RETURN_OK   0
#define RETURN_ERR  (-1)
#define wifi_hal_dbg_print(format, ...)    wifi_hal_print(WIFI_HAL_LOG_LVL_DEBUG, format, ##__VA_ARGS__)
#define wifi_hal_info_print(format, ...)   wifi_hal_print(WIFI_HAL_LOG_LVL_INFO, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)  wifi_hal_print(WIFI_HAL_LOG_LVL_ERROR, format, ##__VA_ARGS__)

typedef struct { int freq; } hcf_hostapd_iface_t;
typedef struct { unsigned int radio_index; } wifi_vap_info_t;
typedef struct { int countryCode; unsigned char operatingClass; unsigned char channel; } wifi_radio_operationParam_t;
typedef struct { wifi_radio_operationParam_t oper_param; } wifi_radio_info_t;
typedef struct { wifi_vap_info_t vap_info; union { struct { struct { hcf_hostapd_iface_t *iface; } hapd; } ap; } u; } wifi_interface_info_t;

/* the world, owned by the runner */
extern wifi_interface_info_t *hshf_interface;   /* NULL = no interface for any ap index */
extern unsigned int           hshf_interface_vap_index;
extern wifi_radio_info_t     *hshf_radio;       /* NULL = no radio */
extern unsigned int           hshf_radio_index;
extern char                   hshf_last_country[16];

static wifi_interface_info_t *get_interface_by_vap_index(unsigned int vap_index)
{
    return (hshf_interface && hshf_interface_vap_index == vap_index) ? hshf_interface : NULL;
}
static wifi_radio_info_t *get_radio_by_rdk_index(unsigned int index)
{
    return (hshf_radio && hshf_radio_index == index) ? hshf_radio : NULL;
}
static int get_coutry_str_from_code(int code, char *country)
{
    static const struct { int c; const char *s; } map[] = { {1,"US"}, {2,"CA"}, {3,"JP"}, {4,"CN"}, {5,"DE"}, {6,"GB"} };
    int value_updated = 0;
    for (unsigned i = 0; i < sizeof(map)/sizeof(map[0]); i++)
        if (map[i].c == code) { strcpy(country, map[i].s); value_updated = 1; break; }
    if (!value_updated) strcpy(country, "US");
    return RETURN_OK;
}
static int ieee80211_chan_to_freq(const char *country, unsigned char op_class, unsigned char chan)
{
    snprintf(hshf_last_country, sizeof(hshf_last_country), "%s", country);
    switch (op_class) {
    case 81:  return (chan >= 1 && chan <= 13) ? 2407 + 5 * chan : -1;            /* 2.4 GHz */
    case 82:  return chan == 14 ? 2484 : -1;
    case 115: case 118: case 121: case 124: case 125: case 128: case 129: case 130:   /* 5 GHz */
        return (chan >= 36 && chan <= 177) ? 5000 + 5 * chan : -1;
    case 131: case 132: case 133: case 134: case 135: return (chan >= 1 && chan <= 233) ? 5950 + 5 * chan : -1;   /* 6 GHz */
    }
    return -1;
}

/* --- copied from hal_ipc_processors.c:44 --- */
int sync_hostapd_freq_param(unsigned int apIndex)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    wifi_radio_info_t *radio;
    wifi_radio_operationParam_t *radio_param;
    int freq;
    char country[8] = { 0 };

    interface = get_interface_by_vap_index(apIndex);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: interface for ap index:%u not found\n", __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
    vap = &interface->vap_info;
    radio = get_radio_by_rdk_index(vap->radio_index);
#if RDK_SHF_FIX
    /* FIX 1: get_radio_by_rdk_index() returns NULL when no radio has that index. */
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d: radio index:%u for ap index:%u not found\n", __func__, __LINE__, vap->radio_index, apIndex);
        return RETURN_ERR;
    }
#endif
    radio_param = &radio->oper_param;

    get_coutry_str_from_code(radio_param->countryCode, country);

    freq = ieee80211_chan_to_freq(country, radio_param->operatingClass, radio_param->channel);
#if RDK_SHF_FIX
    /* FIX 2: ieee80211_chan_to_freq() returns -1 for an unknown op class / channel; that must not be
     * written into the running hostapd interface. */
    if (freq <= 0) {
        wifi_hal_error_print("%s:%d: ap index:%u no frequency for op class:%u channel:%u\n", __func__, __LINE__, apIndex, radio_param->operatingClass, radio_param->channel);
        return RETURN_ERR;
    }
    /* FIX 3: hapd.iface is NULL until hostapd has created the interface (other code checks it). */
    if (interface->u.ap.hapd.iface == NULL) {
        wifi_hal_error_print("%s:%d: ap index:%u hostapd interface not created\n", __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
#endif
    if (interface->u.ap.hapd.iface->freq != freq) {
        wifi_hal_info_print("%s:%d: ap index:%u existing freq:%d curr freq:%d\n", __func__, __LINE__, apIndex, interface->u.ap.hapd.iface->freq, freq);
        interface->u.ap.hapd.iface->freq = freq;
    } else {
        wifi_hal_dbg_print("%s:%d: ap index:%u existing freq:%d curr freq:%d\n", __func__, __LINE__, apIndex, interface->u.ap.hapd.iface->freq, freq);
    }
    return RETURN_OK;
}

int sync_hostapd_freq_param_entry(unsigned int apIndex) { return sync_hostapd_freq_param(apIndex); }
