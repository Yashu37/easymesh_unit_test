/*
 * HANDLER: start_sta_channel_scan
 *
 * Function copied VERBATIM from OneWifi source/apps/easyconnect/wifi_easyconnect.c
 * (only "static" dropped so the runner can call it). No fixes. Local arrays:
 *   - radio_mac (mac_address_t,6) <- mac_address_from_name (bounded)
 *   - country[8]  <- get_coutry_str_from_code (bounded by the stub)
 *   - channels[64] (int) <- filled in a loop:
 *         channels[num_channels] = scan_req->operating_classes[i].channels[j];
 *         num_channels++;
 *     with NO bound check against 64; num_channels runs over the REQUEST's
 *     operating_classes[i].num_channels (a peer-controlled UINT). If that
 *     exceeds 64, channels[64] overflows (and the source channels[j] is
 *     over-read). BUG under test.
 *
 * channels[64] is an internal stack array (ASan stack redzones), so the
 * overflow write is caught. The RUNNER poisons the caller scan_req past the
 * struct and the wifi_mgr stand-in past its size.
 *
 * Scaffolding (NOT the function under test): all helpers are file-local stubs;
 * mac_address_from_name writes a fixed MAC so one radio_interface_map entry
 * matches scan_req->ruid.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "common.h"

#define WIFI_EC 0
#define RETURN_OK 0
#define WIFI_RADIO_SCAN_MODE_OFFCHAN 0
#define SCAN_DWELL_MS 20
#define MACSTRFMT "%s"
#define MAC2STR(x) "mac"
typedef struct { unsigned int channel; int band; int DfsEnabled; } wifi_radio_operationParam_t;
typedef struct { int dummy; } wifi_radio_capabilities_t;

static void ssc_print(int m,const char*f,...){char sc[512];va_list ap;(void)m;va_start(ap,f);vsnprintf(sc,sizeof(sc),f,ap);va_end(ap);}
#define wifi_util_dbg_print   ssc_print
#define wifi_util_error_print ssc_print
static wifi_mgr_t *get_wifimgr_obj(void){return (wifi_mgr_t*)ssc_mgr_buf;}
static void mac_address_from_name(char*name,unsigned char*mac){(void)name;mac[0]=0x10;mac[1]=0x11;mac[2]=0x12;mac[3]=0x13;mac[4]=0x14;mac[5]=0x15;}
static wifi_radio_operationParam_t ssc_op = {36,0,0};
static wifi_radio_operationParam_t *getRadioOperationParam(int ri){(void)ri;return &ssc_op;}
static wifi_radio_capabilities_t ssc_cap = {0};
static wifi_radio_capabilities_t *getRadioCapability(int ri){(void)ri;return &ssc_cap;}
static int get_allowed_channels(int band,wifi_radio_capabilities_t*c,int*ch,int*num,int dfs){(void)band;(void)c;(void)dfs;ch[0]=36;ch[1]=40;*num=2;return RETURN_OK;}
static void get_coutry_str_from_code(int code,char*country){(void)code;snprintf(country,8,"US");}
static int country_to_global_op_class(char*country,int opclass){(void)country;(void)opclass;return ssc_global_op_class;}
static int wifi_hal_startScan(int ri,int mode,int dwell,int num,int*ch){(void)ri;(void)mode;(void)dwell;(void)num;(void)ch;ssc_scan_calls++;ssc_scan_num=num;return RETURN_OK;}

/* --- copied verbatim from source/apps/easyconnect/wifi_easyconnect.c (only "static" dropped) --- */
void start_sta_channel_scan(void *data, unsigned int len)
{
    mac_address_t radio_mac;
    wifi_platform_property_t *wifi_prop;
    wifi_radio_capabilities_t *wifi_cap = NULL;
    wifi_radio_operationParam_t *radioOperation = NULL;
    int num_channels = 0;
    int channels[64] = { 0 };
    unsigned int global_op_class = 0;
    char country[8] = { 0 };

    radio_interface_mapping_t *radio_iface_map = NULL;
    channel_scan_request_t *scan_req = (channel_scan_request_t *)data;
    wifi_mgr_t *mgr = get_wifimgr_obj();
    bool found_radio = false;

    if (scan_req == NULL) {
        wifi_util_error_print(WIFI_EC, "%s:%d NUll data Pointer\n", __func__, __LINE__);
        return;
    }

    if (len < sizeof(channel_scan_request_t)) {
        wifi_util_error_print(WIFI_EC, "%s:%d Invalid parameter size \n", __func__, __LINE__);
        return;
    }

    if (mgr == NULL) {
        wifi_util_error_print(WIFI_EC, "%s:%d Mgr object is NULL \n", __func__, __LINE__);
        return;
    }

    wifi_prop = &mgr->hal_cap.wifi_prop;

    for (unsigned int k = 0;
         k < (sizeof(wifi_prop->radio_interface_map) / sizeof(radio_interface_mapping_t)); k++) {
        radio_iface_map = &(wifi_prop->radio_interface_map[k]);
        if (radio_iface_map == NULL) {
            wifi_util_error_print(WIFI_EC, "%s:%d: Unable to find the radio interface map entry \n",
                __func__, __LINE__);
            return;
        }
        mac_address_from_name(radio_iface_map->interface_name, radio_mac);
        if (memcmp(scan_req->ruid, radio_mac, sizeof(mac_addr_t)) == 0) {
            wifi_util_dbg_print(WIFI_EC,
                "%s:%d Processing channel scan for Radio : " MACSTRFMT "\n", __func__, __LINE__,
                MAC2STR(radio_mac));
            found_radio = true;
            break;
        }
    }

    if (!found_radio) {
        wifi_util_dbg_print(WIFI_EC, "%s:%d Failed to find radio for MAC : " MACSTRFMT "\n",
            __func__, __LINE__, MAC2STR(radio_mac));
        return;
    }

    radioOperation = getRadioOperationParam(radio_iface_map->radio_index);
    if (radioOperation == NULL) {
        wifi_util_error_print(WIFI_EC, "%s:%d NULL radioOperation pointer for radio : %d\n",
            __func__, __LINE__, radio_iface_map->radio_index);
        return;
    }

    wifi_cap = getRadioCapability(radio_iface_map->radio_index);

    if (scan_req->num_operating_classes == 0) {
        if (get_allowed_channels(radioOperation->band, wifi_cap, channels, &num_channels,
                radioOperation->DfsEnabled) != RETURN_OK) {
            wifi_util_error_print(WIFI_EC, "%s:%d get allowed channels failed for the radio : %d\n",
                __func__, __LINE__, radio_iface_map->radio_index);
            return;
        }
    } else {
        get_coutry_str_from_code(mgr->radio_config[radio_iface_map->radio_index].oper.countryCode,
            country);
        global_op_class = country_to_global_op_class(country,
            mgr->radio_config[radio_iface_map->radio_index].oper.operatingClass);

        for (int i = 0; i < scan_req->num_operating_classes; i++) {
            if (scan_req->operating_classes[i].operating_class == global_op_class) {
                for (int j = 0; j < scan_req->operating_classes[i].num_channels; j++) {
                    channels[num_channels] = scan_req->operating_classes[i].channels[j];
                    wifi_util_dbg_print(WIFI_EC, "%s:%d channel number:%u\n", __func__, __LINE__,
                        scan_req->operating_classes[i].channels[j]);
                    num_channels++;
                }
                break;
            }
        }
    }

    if (wifi_hal_startScan(radio_iface_map->radio_index, WIFI_RADIO_SCAN_MODE_OFFCHAN, SCAN_DWELL_MS,
            num_channels, channels) != RETURN_OK) {
        wifi_util_error_print(WIFI_EC, "%s:%d Failed to start station scan on radio: %d\n",
            __func__, __LINE__, radio_iface_map->radio_index);
        return;
    }
    wifi_util_dbg_print(WIFI_EC, "%s:%d Successfully started scan on radio: %d\n", __func__,
        __LINE__, radio_iface_map->radio_index);
}
