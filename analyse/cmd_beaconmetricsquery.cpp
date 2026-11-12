/*
 * HANDLER: cmd_beaconmetricsquery
 *
 * Function copied from unified-wifi-mesh src/ctrl/dm_easy_mesh_ctrl.cpp
 * (develop @ 1ba9529), em_ctrl_t::cmd_beaconmetricsquery, with get_table_instance()
 * and the tr_181_t helpers it calls (verbatim from tr_181_helper.cpp) and
 * util::split_by_delim (verbatim from src/utils/util.cpp). Fixes 2-3 applied (start fix n / end fix n markers).
 * Local arrays: instance[32], bssid[33], ssid[33], elem_list[129],
 * ch_rep_items[6] (each ch_list[64]), buff[sizeof(em_subdoc_info_t)+EM_IO_BUFF_SZ].
 * Scaffolding: one device / radio / BSS / STA (numeric index 1 or MAC alias),
 * io_process records what is sent. cJSON is the real library.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <stdint.h>
#include <sstream>
#include <string>
#include <vector>
#include "common.h"

namespace cbm {

/* bus types come from the ccs section of common.h (the global ones differ in other harnesses) */
using ccs::bus_error_t;
using ccs::bus_error_success; using ccs::bus_error_general; using ccs::bus_error_invalid_input;
using ccs::bus_error_out_of_resources; using ccs::bus_error_invalid_method; using ccs::bus_error_invalid_namespace;
using ccs::bus_data_type_t; using ccs::bus_data_type_string;
using ccs::bus_data_type_int8; using ccs::bus_data_type_uint8; using ccs::bus_data_type_int16;
using ccs::bus_data_type_uint16; using ccs::bus_data_type_int32; using ccs::bus_data_type_uint32;
using ccs::raw_data_t; using ccs::bus_data_prop_t;

#define TR181_SSID_MAX_LEN         32
#define TR181_BSSID_MAX_LEN        32
#define TR181_ELEMLIST_MAX_LEN     128
#define TR181_CHANREP_MAX_CNT      6
#undef EM_MAX_CHANNELS_IN_LIST
#define EM_MAX_CHANNELS_IN_LIST    64
#ifndef MAX_INSTANCE_LEN
#define MAX_INSTANCE_LEN 32
#endif
#define DATAELEMS_NETWORK "Device.WiFi.DataElements.Network."
#define EM_IO_BUFF_SZ 4096
#undef GLOBAL_NET_ID
#define GLOBAL_NET_ID "OneWifiMesh"
typedef char mac_addr_str_t[18];
typedef struct { int op_class; char ch_list[EM_MAX_CHANNELS_IN_LIST]; } tr181_bmq_ch_rep_item_t;
typedef struct { char name[64]; char buff[0]; } __attribute__((__packed__)) em_subdoc_info_t;
typedef enum { em_bus_event_type_beacon_query = 1 } em_bus_event_type_t;

/* --- scaffolding: dm / controller stand-ins --- */
typedef struct { struct { unsigned char mac[6]; } intf; } em_device_info_t;
typedef struct { struct { unsigned char ruid[6]; } id; } em_radio_info_t;
typedef struct { struct { unsigned char mac[6]; } bssid; } em_bss_info_t;
typedef struct { unsigned char id[6]; } em_sta_info_t;
class dm_device_t { public: em_device_info_t info; em_device_info_t *get_device_info() { return &info; } };
class dm_radio_t  { public: em_radio_info_t info; em_radio_info_t *get_radio_info() { return &info; } };
class dm_bss_t    { public: em_bss_info_t info; em_bss_info_t *get_bss_info() { return &info; } };
class dm_sta_t    { public: em_sta_info_t info; em_sta_info_t *get_sta_info() { return &info; } };
class dm_easy_mesh_t {
public:
    dm_device_t device; dm_radio_t radio; dm_bss_t bss; dm_sta_t sta;
    dm_device_t *get_device() { return &device; }
    static void macbytes_to_string(unsigned char *mac, char *string)
    { snprintf(string, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); }
};
class dm_easy_mesh_ctrl_t {
public:
    dm_easy_mesh_t dm;
    dm_easy_mesh_ctrl_t() {
        unsigned char d[6] = {2,0,0,0,0,1}, r[6] = {2,0,0,0,0x10,1}, b[6] = {2,0,0,0,0x20,1}, s[6] = {2,0,0,0,0x30,1};
        memcpy(dm.device.info.intf.mac, d, 6); memcpy(dm.radio.info.id.ruid, r, 6);
        memcpy(dm.bss.info.bssid.mac, b, 6); memcpy(dm.sta.info.id, s, 6);
    }
    static bool match(unsigned char *mac, char *instance, bool is_num)
    {   char str[18];
        if (is_num) return atoi(instance) == 1;
        dm_easy_mesh_t::macbytes_to_string(mac, str);
        return strcmp(instance, str) == 0;
    }
    const char* get_table_instance(const char *src, char *instance, size_t max_len, bool *is_num);
    dm_easy_mesh_t *get_dm_easy_mesh(char *instance, bool is_num) { return match(dm.device.info.intf.mac, instance, is_num) ? &dm : NULL; }
    dm_radio_t *get_dm_radio(dm_easy_mesh_t *d, char *instance, bool is_num) { return match(d->radio.info.id.ruid, instance, is_num) ? &d->radio : NULL; }
    dm_bss_t *get_dm_bss(dm_easy_mesh_t *d, em_radio_info_t *ri, char *instance, bool is_num) { (void)ri; return match(d->bss.info.bssid.mac, instance, is_num) ? &d->bss : NULL; }
    dm_sta_t *get_dm_sta(dm_easy_mesh_t *d, em_bss_info_t *bi, char *instance, bool is_num) { (void)bi; return match(d->sta.info.id, instance, is_num) ? &d->sta : NULL; }
};
int io_calls = 0;
char io_json[EM_IO_BUFF_SZ + 64];
unsigned int io_len = 0;
char last_status[16];
class em_ctrl_t {
public:
    dm_easy_mesh_ctrl_t m_data_model;
    static em_ctrl_t *get_em_ctrl_instance();
    dm_easy_mesh_ctrl_t *get_dm_ctrl() { return &m_data_model; }
    void io_process(em_bus_event_type_t type, char *data, unsigned int len)
    {   (void)type; io_calls++; io_len = len;
        memset(io_json, 0, sizeof(io_json));
        memcpy(io_json, data, len < sizeof(io_json) ? len : sizeof(io_json) - 1);
    }
    static bus_error_t cmd_beaconmetricsquery(const char *method_name, const bus_data_prop_t *input_params, bus_data_prop_t **output_params, void *async_handle);
};
em_ctrl_t *ctrl_instance_ptr = NULL;
em_ctrl_t *em_ctrl_t::get_em_ctrl_instance() { return ctrl_instance_ptr; }

class tr_181_t {
public:
    static bool parse_object_index(const char *name, int *index);
    static bool parse_bmq_ch_rep_obj(const bus_data_prop_t *prop, tr181_bmq_ch_rep_item_t *ch_rep_item);
    static bool tr181_copy_prop_string(const bus_data_prop_t *prop, char *dst, size_t dst_len);
    static bool tr181_get_prop_int(const bus_data_prop_t *prop, int *value);
    static bus_data_prop_t *tr181_set_status_output_prop(const char *status)
    {   /* stand-in for tr181_alloc_string_prop("Status", status) */
        bus_data_prop_t *p = (bus_data_prop_t *)calloc(1, sizeof(*p));
        snprintf(last_status, sizeof(last_status), "%s", status);
        p->value.data_type = bus_data_type_string;
        p->value.raw_data.bytes = strdup(status);
        return p;
    }
};
struct util { static std::vector<std::string> split_by_delim(const std::string& s, char delimiter); };

/* --- copied verbatim from src/utils/util.cpp --- */
std::vector<std::string> util::split_by_delim(const std::string& s, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    
    return tokens;
}

/* --- copied verbatim from src/ctrl/tr_181/wfa_data_model/tr_181_helper.cpp --- */
bool tr_181_t::parse_object_index(const char *name, int *index)
{
    if (!name || !index) {
        em_printfout("name or index invalid");
        return false;
    }

    const char *src = strchr(name, '.');
    if (!src || !*(src + 1)) {
        em_printfout("invalid name format");
        return false;
    }

    ++src;
    char instance[MAX_INSTANCE_LEN] = { 0 };
    size_t len = 0;
    while (src[len] && src[len] != '.' && len < sizeof(instance) - 1) {
        if (!isdigit(static_cast<unsigned char> (src[len]))) {
            em_printfout("invalid name format");
            return false;
        }
        instance[len] = src[len];
        ++len;
    }

    if ((len == 0) || (src[len] && (src[len] != '.'))) {
        em_printfout("invalid name format");
        return false;
    }

    char *ep = NULL;
    long val = strtol(instance, &ep, 10);
    if (!ep || *ep != '\0' || val <= 0 || val > UINT8_MAX) {
        em_printfout("invalid name format");
        return false;
    }

    *index = static_cast<int>(val);

    return true;
}

bool tr_181_t::parse_bmq_ch_rep_obj(const bus_data_prop_t *prop, tr181_bmq_ch_rep_item_t *ch_rep_item)
{
     if (!prop || !ch_rep_item) {
         return false;
     }

    const char *name = prop->name;

    /* APChannelReport.{i}.OperatingClass or APChannelReport.{i}.ChannelList */
    name += sizeof("APChannelReport");
    name  = strstr(name, ".");
    if (!name) {
        return false;
    }

    ++name;
    if (strcmp(name, "OperatingClass") == 0) {
        if (!tr_181_t::tr181_get_prop_int(prop, &ch_rep_item->op_class)) {
            return false;
        }
    } else if (strcmp(name, "ChannelList") == 0) {
        if (!tr_181_t::tr181_copy_prop_string(prop, ch_rep_item->ch_list, sizeof(ch_rep_item->ch_list))) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool tr_181_t::tr181_copy_prop_string(const bus_data_prop_t *prop, char *dst, size_t dst_len)
{
    if (!prop || !dst || (dst_len == 0U)) {
        return false;
    }
    if ((prop->value.data_type != bus_data_type_string) || !prop->value.raw_data.bytes) {
        return false;
    }

    const char *src = static_cast<const char *>(prop->value.raw_data.bytes);
    size_t len = prop->value.raw_data_len;
    if (len == 0U) {
        len = strnlen(src, dst_len - 1U);
    } else if (src[len - 1U] == '\0') {
        len -= 1U;
    }
    if (len >= dst_len) {
        len = dst_len - 1U;
    }

    memcpy(dst, src, len);
    dst[len] = '\0';
    return true;
}

bool tr_181_t::tr181_get_prop_int(const bus_data_prop_t *prop, int *value)
{
    if (!prop || !value) {
        return false;
    }

    if (prop->value.data_type == bus_data_type_int8) {
        *value = static_cast<int>(prop->value.raw_data.i8);
    } else if (prop->value.data_type == bus_data_type_uint8) {
        *value = static_cast<int>(prop->value.raw_data.u8);
    } else if (prop->value.data_type == bus_data_type_int16) {
        *value = static_cast<int>(prop->value.raw_data.i16);
    } else if (prop->value.data_type == bus_data_type_uint16) {
        *value = static_cast<int>(prop->value.raw_data.u16);
    } else if (prop->value.data_type == bus_data_type_int32) {
        *value = prop->value.raw_data.i32;
    } else if (prop->value.data_type == bus_data_type_uint32) {
        *value = static_cast<int>(prop->value.raw_data.u32);
    } else {
        return false;
    }

    return true;
}

/* --- copied from src/ctrl/dm_easy_mesh_ctrl.cpp (verbatim apart from the fixes) --- */
const char* dm_easy_mesh_ctrl_t::get_table_instance(const char *src, char *instance, size_t max_len, bool *is_num)
{
	char *dst = instance;
	size_t len = 0;

/* start updated fix 3 */
    if (src == NULL) {
        return NULL;
    }
/* end updated fix 3 */
    src = strstr(src, ".");
/* start fix 3 */
    if (src == NULL) {
        return NULL;
    }
/* end fix 3 */
    ++src;

	if (*src == '[') {
		*is_num = false;
		++src;
		while (*src && *src != ']' && ++len < max_len) {
			*dst++ = *src++;
		}
		*dst++ = 0;
/* start updated fix 3 */
        if (*src != ']' || src[1] != '.') {
            return NULL;
        }
        src += 2;
/* end updated fix 3 */
	} else {
		*is_num = true;
		while (*src && *src != '.' && ++len < max_len) {
			*dst++ = *src++;
		}
		*dst++ = 0;
/* start fix 3 */
        if (*src) {
            src++;
        }
/* end fix 3 */
	}

	return src;
}

bus_error_t em_ctrl_t::cmd_beaconmetricsquery(const char *method_name, const bus_data_prop_t *input_params, bus_data_prop_t **output_params, void *async_handle)
{
    (void)async_handle;
    const char *name = method_name;
    const char *param;
    char instance[MAX_INSTANCE_LEN] = { 0 };
    bool is_num;
    const bus_data_prop_t *prop = NULL;
    int op_class = -1;
    int channel_num = -1;
    int rep_detail = -1;
    int ch_rep_idx;
    unsigned int ch_rep_cnt = 0;
    const char *wildcard_mac = "FF:FF:FF:FF:FF:FF";
    char bssid[TR181_BSSID_MAX_LEN + 1] = { 0 };
    char ssid[TR181_SSID_MAX_LEN + 1] = { 0 };
    char elem_list[TR181_ELEMLIST_MAX_LEN + 1] = { 0 };
    tr181_bmq_ch_rep_item_t ch_rep_items[TR181_CHANREP_MAX_CNT] = { 0, 0, 0 };
    em_subdoc_info_t *subdoc = NULL;
    alignas(em_subdoc_info_t) unsigned char buff[sizeof(em_subdoc_info_t) + EM_IO_BUFF_SZ];
    cJSON *root = NULL, *json = NULL, *net_obj = NULL;
    cJSON *dev_arr = NULL, *dev_obj = NULL;
    cJSON *radio_arr = NULL, *radio_obj = NULL;
    cJSON *bss_arr = NULL, *bss_obj = NULL;
    cJSON *sta_arr = NULL, *sta_obj = NULL;
    cJSON *bmquery_obj = NULL;
    cJSON *chrep_arr = NULL, *chrep_obj = NULL;
    cJSON *chlist_arr = NULL, *chlist_obj = NULL;
    cJSON *elemlist_arr = NULL, *elemlist_obj = NULL;
    mac_addr_str_t mac_str;
    char *json_buff = NULL;
    size_t json_len = 0;
    bus_error_t rc;

    param = (name ? strrchr(name, '.') : NULL);
    if (param == NULL) {
        em_printfout("Invalid method name");
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_invalid_input;
    }
    ++param;
    if (strcmp("X_AIRTIES_BeaconMetricsQuery()", param) != 0) {
        em_printfout("Invalid method");
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_invalid_method;
    }

    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();
    if (!em_ctrl) {
        em_printfout("Controller not found");
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_general;
    }
    dm_easy_mesh_ctrl_t *dm_ctrl = em_ctrl->get_dm_ctrl();

    /* Extract device instance (numeric or alias) and find the dm object for
     * that device instance */
/* start fix 2 */
    if (strlen(name) < sizeof(DATAELEMS_NETWORK)) {
        em_printfout("Invalid method path");
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_invalid_namespace;
    }
/* end fix 2 */
    name += sizeof(DATAELEMS_NETWORK);
    name = dm_ctrl->get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
/* start fix 3 */
    if (name == NULL) {
        em_printfout("Invalid method path");
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_invalid_namespace;
    }
/* end fix 3 */
    dm_easy_mesh_t *dm = dm_ctrl->get_dm_easy_mesh(instance, is_num);
    if (dm == NULL) {
        em_printfout("Device not found");
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_invalid_namespace;
    }
    em_device_info_t *di = dm->get_device()->get_device_info();

    /* Extract radio instance (numeric or alias), find the radio dm object
     * for that instance, and finally get info struct for radio dm object */
    name = dm_ctrl->get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
/* start fix 3 */
    if (name == NULL) {
        em_printfout("Radio not found");
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_invalid_namespace;
    }
/* end fix 3 */
    dm_radio_t *radio = dm_ctrl->get_dm_radio(dm, instance, is_num);
    if (radio == NULL) {
        em_printfout("Radio not found");
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_invalid_namespace;
    }
    em_radio_info_t *ri = radio->get_radio_info();

    /* Extract bss instance (numeric or alias), find the bss dm object
     * for that instance, and finally get info struct for bss dm object */
    name = dm_ctrl->get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
/* start fix 3 */
    if (name == NULL) {
        em_printfout("BSS not found");
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_invalid_namespace;
    }
/* end fix 3 */
    dm_bss_t *bss = dm_ctrl->get_dm_bss(dm, ri, instance, is_num);
    if (bss == NULL) {
        em_printfout("BSS not found");
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_invalid_namespace;
    }
    em_bss_info_t *bi = bss->get_bss_info();

    /* Extract sta instance (numeric or alias), find the sta dm object
     * for that instance, and finally get info struct for sta dm object */
    name = dm_ctrl->get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
/* start fix 3 */
    if (name == NULL) {
        em_printfout("STA not found");
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_invalid_namespace;
    }
/* end fix 3 */
    dm_sta_t *sta = dm_ctrl->get_dm_sta(dm, bi, instance, is_num);
    if (sta == NULL) {
        em_printfout("STA not found");
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_invalid_namespace;
    }
    em_sta_info_t *si = sta->get_sta_info();

    /* Most of the parameters are mandatory, parse them */
    for (prop = input_params; prop; prop = prop->next_data) {
        if (strcmp(prop->name, "OperatingClass") == 0) {
            if (!tr_181_t::tr181_get_prop_int(prop, &op_class)) {
                goto invalid;
            }
        } else if (strcmp(prop->name, "Channel") == 0) {
            if (!tr_181_t::tr181_get_prop_int(prop, &channel_num)) {
                goto invalid;
            }
        } else if (strcmp(prop->name, "BSSID") == 0) {
            if (!tr_181_t::tr181_copy_prop_string(prop, bssid, sizeof(bssid))) {
                goto invalid;
            }
        } else if (strcmp(prop->name, "ReportingDetail") == 0) {
            if (!tr_181_t::tr181_get_prop_int(prop, &rep_detail)) {
                goto invalid;
            }
        } else if (strcmp(prop->name, "SSID") == 0) {
            if (!tr_181_t::tr181_copy_prop_string(prop, ssid, sizeof(ssid))) {
                goto invalid;
            }
        } else if (strncmp(prop->name, "APChannelReport.", sizeof("APChannelReport.") - 1) == 0) {
            if (!tr_181_t::parse_object_index(prop->name, &ch_rep_idx)) {
                em_printfout("Parse channel report index failed");
                goto invalid;
            }
            if (ch_rep_idx < 1 || ch_rep_idx > TR181_CHANREP_MAX_CNT) {
                em_printfout("Invalid channel report index: %d", ch_rep_idx);
                goto invalid;
            }
            if (ch_rep_idx > static_cast<int> (ch_rep_cnt)) {
                ch_rep_cnt = static_cast<unsigned int> (ch_rep_idx);
            }
            --ch_rep_idx;
            if (!tr_181_t::parse_bmq_ch_rep_obj(prop, &ch_rep_items[ch_rep_idx])) {
                em_printfout("Parse channel report object failed");
                goto invalid;
            }
        } else if (strcmp(prop->name, "ElementIDList") == 0) {
            if (!tr_181_t::tr181_copy_prop_string(prop, elem_list, sizeof(elem_list))) {
                goto invalid;
            }
        } else {
invalid:
            em_printfout("Invalid parameter: %s", prop->name);
            if (output_params) {
                *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
            }
            return bus_error_invalid_input;
        }
    }
    /* Mandatory parameters: OperatingClass, Channel, SSID,
     *                       APChannelReport if Channel is 255 and
     *                       ElementIDList if ReportingDetail is 1
     * Note: Wi-Fi EasyMesh Specification allows SSID to be omitted via setting SSID Length
     *       field in 17.2.27 to zero (10.3.3), but this implementation mandates SSID to be
     *       specified. */
    if (op_class < 0 || channel_num < 0 || !ssid[0] ||
        (channel_num == 255 && !ch_rep_cnt) || (rep_detail == 1 && !elem_list[0])) {
        em_printfout("Mandatory parameters missing");
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_invalid_input;
    }
    for (unsigned int c = 0; c < ch_rep_cnt; c++) {
        tr181_bmq_ch_rep_item_t *ch_rep_item = &ch_rep_items[c];
        if (ch_rep_item->op_class <= 0 || !ch_rep_item->ch_list[0]) {
            em_printfout("Invalid APChannelReport[%d] parameter", c);
            if (output_params) {
                *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
            }
            return bus_error_invalid_input;
        }
        /* Root cause: OneWifi's wifi_BeaconRequest_t::channelReport carries a single
         * opClass for the whole flattened channel list -- em_agent.cpp's
         * send_beacon_query() assigns beacon_req->channelReport.opClass only from the
         * first AP Channel Report and merges every report's channels under it. Multiple
         * reports with different Operating Class values therefore can't be represented
         * on the wire today, so reject rather than silently send channels under the
         * wrong operating class. Remove this check once OneWifi's HAL struct supports a
         * per-report operating class. */
        if (c > 0 && ch_rep_item->op_class != ch_rep_items[0].op_class) {
            em_printfout("APChannelReport[%d] op_class %d differs from APChannelReport[0] op_class %d; "
                "multiple operating classes are not supported by the HAL channel report today",
                c, ch_rep_item->op_class, ch_rep_items[0].op_class);
            if (output_params) {
                *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
            }
            return bus_error_invalid_input;
        }
    }
    if (!bssid[0]) {
        /* If BSSID is not provided, use wildcard BBSID */
        strncpy(bssid, wildcard_mac, sizeof(bssid) - 1);
    }
    if (rep_detail == -1) {
        /* Reporting detail not provided; default to 0 (not needed) */
        rep_detail = 0;
    } else if (rep_detail < 0 || rep_detail > 2) {
        em_printfout("Invalid ReportingDetail: %d", rep_detail);
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_invalid_input;
    }

    /* Prepare subdoc to be processed with command */
    subdoc = reinterpret_cast<em_subdoc_info_t *>(buff);
    memset(subdoc, 0, sizeof(em_subdoc_info_t));
    strncpy(subdoc->name, "BeaconMetricsQuery", sizeof(subdoc->name) - 1);

    /* Create json with root "wfa-dataelements:BeaconMetricsQuery" and fill
     * with necessary parameters we extract from path */
    rc = bus_error_out_of_resources;
    root = cJSON_CreateObject();
    json = cJSON_CreateObject();
    if (!root || !json) {
        em_printfout("Create object failed");
        goto cleanup;
    }
    if (!cJSON_AddItemToObject(root, "wfa-dataelements:BeaconMetricsQuery", json)) {
        em_printfout("Add item failed");
        cJSON_Delete(json);
        goto cleanup;
    }
    /* Add Network parameters */
    net_obj = cJSON_AddObjectToObject(json, "Network");
    if (!net_obj) {
        em_printfout("Add Network failed");
        goto cleanup;
    }
    if (!cJSON_AddStringToObject(net_obj, "ID", GLOBAL_NET_ID)) {
        em_printfout("Add Network ID failed");
        goto cleanup;
    }
    /* Add Device parameters */
    dev_arr = cJSON_AddArrayToObject(net_obj, "DeviceList");
    if (!dev_arr) {
        em_printfout("Add DeviceList failed");
        goto cleanup;
    }
    dev_obj = cJSON_CreateObject();
    if (!dev_obj) {
        em_printfout("Create object failed");
        goto cleanup;
    }
    if (!cJSON_AddItemToArray(dev_arr, dev_obj)) {
        em_printfout("Add Device failed");
        cJSON_Delete(dev_obj);
        goto cleanup;
    }
    dm_easy_mesh_t::macbytes_to_string(di->intf.mac, mac_str);
    if (!cJSON_AddStringToObject(dev_obj, "ID", mac_str)) {
        em_printfout("Add Device ID failed");
        goto cleanup;
    }
    /* Add Radio parameters */
    radio_arr = cJSON_AddArrayToObject(dev_obj, "RadioList");
    if (!radio_arr) {
        em_printfout("Add RadioList failed");
        goto cleanup;
    }
    radio_obj = cJSON_CreateObject();
    if (!radio_obj) {
        em_printfout("Create object failed");
        goto cleanup;
    }
    if (!cJSON_AddItemToArray(radio_arr, radio_obj)) {
        em_printfout("Add Radio failed");
        cJSON_Delete(radio_obj);
        goto cleanup;
    }
    dm_easy_mesh_t::macbytes_to_string(ri->id.ruid, mac_str);
    if (!cJSON_AddStringToObject(radio_obj, "ID", mac_str)) {
        em_printfout("Add Radio ID failed");
        goto cleanup;
    }
    /* Add BSS parameters */
    bss_arr = cJSON_AddArrayToObject(radio_obj, "BSSList");
    if (!bss_arr) {
        em_printfout("Add BSSList failed");
        goto cleanup;
    }
    bss_obj = cJSON_CreateObject();
    if (!bss_obj) {
        em_printfout("Create object failed");
        goto cleanup;
    }
    if (!cJSON_AddItemToArray(bss_arr, bss_obj)) {
        em_printfout("Add BSS failed");
        cJSON_Delete(bss_obj);
        goto cleanup;
    }
    dm_easy_mesh_t::macbytes_to_string(bi->bssid.mac, mac_str);
    if (!cJSON_AddStringToObject(bss_obj, "BSSID", mac_str)) {
        em_printfout("Add BSSID failed");
        goto cleanup;
    }
    /* Add STA parameters */
    sta_arr = cJSON_AddArrayToObject(bss_obj, "STAList");
    if (!sta_arr) {
        em_printfout("Add STAList failed");
        goto cleanup;
    }
    sta_obj = cJSON_CreateObject();
    if (!sta_obj) {
        em_printfout("Create object failed");
        goto cleanup;
    }
    if (!cJSON_AddItemToArray(sta_arr, sta_obj)) {
        em_printfout("Add STA failed");
        cJSON_Delete(sta_obj);
        goto cleanup;
    }
    dm_easy_mesh_t::macbytes_to_string(si->id, mac_str);
    if (!cJSON_AddStringToObject(sta_obj, "MACAddress", mac_str)) {
        em_printfout("Add MACAddress failed");
        goto cleanup;
    }
    /* Add method parameters */
    bmquery_obj = cJSON_CreateObject();
    if (!bmquery_obj) {
        em_printfout("Create object failed");
        goto cleanup;
    }
    if (!cJSON_AddItemToObject(sta_obj, "BeaconMetricsQuery", bmquery_obj)) {
        em_printfout("Add BeaconMetricsQuery failed");
        cJSON_Delete(bmquery_obj);
        goto cleanup;
    }
    /* TODO: Validity check of parameters? */
    if (!cJSON_AddNumberToObject(bmquery_obj, "OperatingClass", op_class)) {
        em_printfout("Add OperatingClass failed");
        goto cleanup;
    }
    if (!cJSON_AddNumberToObject(bmquery_obj, "Channel", channel_num)) {
        em_printfout("Add Channel failed");
        goto cleanup;
    }
    if (!cJSON_AddNumberToObject(bmquery_obj, "ReportingDetail", rep_detail)) {
        em_printfout("Add ReportingDetail failed");
        goto cleanup;
    }
    if (!cJSON_AddStringToObject(bmquery_obj, "BSSID", bssid)) {
        em_printfout("Add BSSID failed");
        goto cleanup;
    }
    if (!cJSON_AddStringToObject(bmquery_obj, "SSID", ssid)) {
        em_printfout("Add SSID failed");
        goto cleanup;
    }
    if (channel_num == 255) {
        chrep_arr = cJSON_AddArrayToObject(bmquery_obj, "APChReportList");
        if (!chrep_arr) {
            em_printfout("Add APChReportList array failed");
            goto cleanup;
        }
        for (unsigned int c = 0; c < ch_rep_cnt; c++) {
            tr181_bmq_ch_rep_item_t *ch_rep_item = &ch_rep_items[c];
            chrep_obj = cJSON_CreateObject();
            if (!chrep_obj) {
                em_printfout("Create object failed");
                goto cleanup;
            }
            if (!cJSON_AddItemToArray(chrep_arr, chrep_obj)) {
                em_printfout("Add APChReport failed");
                cJSON_Delete(chrep_obj);
                goto cleanup;
            }
            if (!cJSON_AddNumberToObject(chrep_obj, "OpClass", ch_rep_item->op_class)) {
                em_printfout("Add OpClass failed");
                goto cleanup;
            }
            chlist_arr = cJSON_AddArrayToObject(chrep_obj, "ChannelList");
            if (!chlist_arr) {
                em_printfout("Add ChannelList array failed");
                goto cleanup;
            }
            std::string chlist_str = ch_rep_item->ch_list;
            std::vector<std::string> channels = util::split_by_delim(chlist_str, ',');
            for (unsigned int i = 0; i < channels.size(); i++) {
                char *ep = NULL;
                int channel = static_cast<int> (std::strtol(channels[i].c_str(), &ep, 10));
                if (ep == channels[i].c_str() || *ep != '\0') {
                    em_printfout("Invalid channel");
                    rc = bus_error_invalid_input;
                    goto cleanup;
                }
                chlist_obj = cJSON_CreateNumber(channel);
                if (!chlist_obj) {
                    em_printfout("Create number failed");
                    goto cleanup;
                }
                if (!cJSON_AddItemToArray(chlist_arr, chlist_obj)) {
                    em_printfout("Add item failed");
                    cJSON_Delete(chlist_obj);
                    goto cleanup;
                }
            }
        }
    }
    if (rep_detail == 1) {
        elemlist_arr = cJSON_AddArrayToObject(bmquery_obj, "ElementList");
        if (!elemlist_arr) {
            em_printfout("Add ElementList array failed");
            goto cleanup;
        }
        std::string elemlist_str = elem_list;
        std::vector<std::string> elements = util::split_by_delim(elemlist_str, ',');
        for (unsigned int i = 0; i < elements.size(); i++) {
            char *ep = NULL;
            int element = static_cast<int> (std::strtol(elements[i].c_str(), &ep, 10));
            if (ep == elements[i].c_str() || *ep != '\0') {
                em_printfout("Invalid element");
                rc = bus_error_invalid_input;
                goto cleanup;
            }
            elemlist_obj = cJSON_CreateNumber(element);
            if (!elemlist_obj) {
                em_printfout("Create number failed");
                goto cleanup;
            }
            if (!cJSON_AddItemToArray(elemlist_arr, elemlist_obj)) {
                em_printfout("Add item failed");
                cJSON_Delete(elemlist_obj);
                goto cleanup;
            }
        }
    }

    /* Convert JSON back to string and store in subdoc buffer. */
    json_buff = cJSON_PrintUnformatted(root);
    if (!json_buff) {
        em_printfout("Create output buffer failed");
        rc = bus_error_out_of_resources;
        goto cleanup;
    }
    /* Ensure updated JSON fits in buffer. */
    json_len = strlen(json_buff);
    if (json_len >= EM_IO_BUFF_SZ) {
        em_printfout("Buffer too big for subdoc");
        free(json_buff);
        rc = bus_error_invalid_input;
        goto cleanup;
    }
    memcpy(subdoc->buff, json_buff, json_len);
    subdoc->buff[json_len] = '\0';

    // uncomment below lines to log the updated JSON before sending to DM; can be helpful for debugging.
    /*
    cJSON *json_obj;
    json_obj = cJSON_Parse(subdoc->buff);
    if (json_obj) {
        char *new_json = cJSON_Print(json_obj);
        em_printfout("Updated and formatted JSON:\n%s", new_json);
        free(new_json);
        cJSON_Delete(json_obj);
    } else {
        em_printfout("Invalid JSON in subdoc->buff");
    }
    */

    em_ctrl->io_process(em_bus_event_type_beacon_query, subdoc->buff, static_cast<unsigned int>(json_len + 1U));
    free(json_buff);
    cJSON_Delete(root);

    if (output_params) {
        *output_params = tr_181_t::tr181_set_status_output_prop("Success");
    }

    return bus_error_success;

cleanup:
    cJSON_Delete(root);
    if (output_params) {
        *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
    }
    return rc;
}

bus_error_t invoke(const char *method, const bus_data_prop_t *in, bus_data_prop_t **out)
{
    return em_ctrl_t::cmd_beaconmetricsquery(method, in, out, NULL);
}
static em_ctrl_t ctrl_obj;
void set_ctrl(bool present) { ctrl_instance_ptr = present ? &ctrl_obj : NULL; }

} /* namespace cbm */
