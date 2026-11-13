/*
 * HANDLER: cmd_disassociate
 *
 * Function copied (fixes 1-2 applied, start fix n / end fix n markers) from unified-wifi-mesh src/ctrl/dm_easy_mesh_ctrl.cpp
 * (develop @ 1ba9529), em_ctrl_t::cmd_disassociate, with get_table_instance() (same file),
 * the tr_181_t helpers it calls (tr_181_helper.cpp) and util::split_by_delim (src/utils/util.cpp).
 * Local arrays: instance[32], buff[sizeof(em_subdoc_info_t)+EM_IO_BUFF_SZ].
 * Scaffolding: one device 1 / radio 1 / BSS 1 / STA 1 (or MAC aliases 02:00:00:00:00:01 / :10:01 /
 * :10:11 / :10:21), io_process records what is sent. cJSON is the real library.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>
#include <string>
#include <vector>
#include "cmd_disassociate.h"

namespace cda {

using ccs::bus_error_t;
using ccs::bus_error_success; using ccs::bus_error_general; using ccs::bus_error_invalid_input;
using ccs::bus_error_out_of_resources; using ccs::bus_error_invalid_method; using ccs::bus_error_invalid_namespace;
using ccs::bus_data_type_t; using ccs::bus_data_type_string;
using ccs::bus_data_type_int8; using ccs::bus_data_type_uint8; using ccs::bus_data_type_int16;
using ccs::bus_data_type_uint16; using ccs::bus_data_type_int32; using ccs::bus_data_type_uint32;
using ccs::raw_data_t; using ccs::bus_data_prop_t;

#define TR181_BSSID_MAX_LEN        32
#define TR181_REQMODE_MAX_LEN      24
#include <strings.h>
#include <limits.h>
#ifndef MAX_INSTANCE_LEN
#define MAX_INSTANCE_LEN 32
#endif
#define DATAELEMS_NETWORK "Device.WiFi.DataElements.Network."
#define EM_IO_BUFF_SZ 4096
#undef GLOBAL_NET_ID
#define GLOBAL_NET_ID "OneWifiMesh"
typedef char mac_addr_str_t[18];
typedef struct { char name[64]; char buff[0]; } __attribute__((__packed__)) em_subdoc_info_t;
typedef enum { em_bus_event_type_disassoc_sta = 1 } em_bus_event_type_t;
typedef enum { em_steering_req_mode_opportunity = 0, em_steering_req_mode_mandate = 1 } em_steering_req_mode_t;

/* --- scaffolding: dm / controller stand-ins --- */
typedef struct { struct { unsigned char mac[6]; } intf; } em_device_info_t;
typedef struct { struct { unsigned char ruid[6]; } id; } em_radio_info_t;
typedef struct { struct { unsigned char mac[6]; } bssid; } em_bss_info_t;
typedef struct { unsigned char id[6]; bool associated; } em_sta_info_t;
class dm_sta_t { public: em_sta_info_t info; em_sta_info_t *get_sta_info() { return &info; } };
class dm_bss_t { public: em_bss_info_t info; em_bss_info_t *get_bss_info() { return &info; } };
class dm_device_t { public: em_device_info_t info; em_device_info_t *get_device_info() { return &info; } };
class dm_radio_t  { public: em_radio_info_t info; em_radio_info_t *get_radio_info() { return &info; } };
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
        unsigned char d[6] = {2,0,0,0,0,1}, r[6] = {2,0,0,0,0x10,1};
        memcpy(dm.device.info.intf.mac, d, 6); memcpy(dm.radio.info.id.ruid, r, 6);
        unsigned char b[6] = {2,0,0,0,0x10,0x11}; memcpy(dm.bss.info.bssid.mac, b, 6);
        unsigned char s[6] = {2,0,0,0,0x10,0x21}; memcpy(dm.sta.info.id, s, 6); dm.sta.info.associated = true;
    }
    static bool match(unsigned char *mac, char *instance, bool is_num)
    {   char str[18];
        if (is_num) return atoi(instance) == 1;
        dm_easy_mesh_t::macbytes_to_string(mac, str);
        return strcmp(instance, str) == 0;
    }
    const char* get_table_instance(const char *src, char *instance, size_t max_len, bool *is_num);
    dm_easy_mesh_t *get_dm_easy_mesh(char *instance, bool is_num) { return match(dm.device.info.intf.mac, instance, is_num) ? &dm : NULL; }
    dm_bss_t *get_dm_bss(dm_easy_mesh_t *d, em_radio_info_t *r, char *instance, bool is_num) { (void)r; return match(d->bss.info.bssid.mac, instance, is_num) ? &d->bss : NULL; }
    dm_sta_t *get_dm_sta(dm_easy_mesh_t *d, em_bss_info_t *b, char *instance, bool is_num) { (void)b; return match(d->sta.info.id, instance, is_num) ? &d->sta : NULL; }
    dm_radio_t *get_dm_radio(dm_easy_mesh_t *d, char *instance, bool is_num) { return match(d->radio.info.id.ruid, instance, is_num) ? &d->radio : NULL; }
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
    static bus_error_t cmd_disassociate(const char *method_name, const bus_data_prop_t *input_params, bus_data_prop_t **output_params, void *async_handle);
};
em_ctrl_t *ctrl_instance_ptr = NULL;
em_ctrl_t *em_ctrl_t::get_em_ctrl_instance() { return ctrl_instance_ptr; }

class tr_181_t {
public:
    static bool tr181_copy_prop_string(const bus_data_prop_t *prop, char *dst, size_t dst_len);
    static bool tr181_get_prop_int(const bus_data_prop_t *prop, int *value);
    static bool tr181_get_prop_bool(const bus_data_prop_t *prop, bool *value);
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

/* tr181_get_prop_bool: verbatim except raw_data.b -> raw_data.u8 (the harness union has no b member) */
#define bus_data_type_boolean ((ccs::bus_data_type_t)100)
bool tr_181_t::tr181_get_prop_bool(const bus_data_prop_t *prop, bool *value)
{
    if (!prop || !value) {
        return false;
    }

    if (prop->value.data_type == bus_data_type_boolean) {
        *value = prop->value.raw_data.u8;
    } else {
        return false;
    }

    return true;
}

/* --- copied verbatim from src/ctrl/dm_easy_mesh_ctrl.cpp --- */
const char* dm_easy_mesh_ctrl_t::get_table_instance(const char *src, char *instance, size_t max_len, bool *is_num)
{
	char *dst = instance;
	size_t len = 0;

/* start fix 2 */
    if (src == NULL) {
        return NULL;
    }
    src = strstr(src, ".");
    if (src == NULL) {
        return NULL;
    }
/* end fix 2 */
    ++src;

	if (*src == '[') {
		*is_num = false;
		++src;
		while (*src && *src != ']' && ++len < max_len) {
			*dst++ = *src++;
		}
		*dst++ = 0;
/* start fix 2 */
        if (*src != ']' || src[1] != '.') {
            return NULL;
        }
        src += 2;
/* end fix 2 */
	} else {
		*is_num = true;
		while (*src && *src != '.' && ++len < max_len) {
			*dst++ = *src++;
		}
		*dst++ = 0;
/* start fix 2 */
        if (*src) {
            src++;
        }
/* end fix 2 */
	}

	return src;
}

bus_error_t em_ctrl_t::cmd_disassociate(const char *method_name, const bus_data_prop_t *input_params, bus_data_prop_t **output_params, void *async_handle)
{
    (void)async_handle;
    const char *name = method_name;
    const char *param;
    char instance[MAX_INSTANCE_LEN] = { 0 };
    bool is_num;
    em_subdoc_info_t *subdoc = NULL;
    unsigned char buff[sizeof(em_subdoc_info_t) + EM_IO_BUFF_SZ];
    cJSON *root = NULL, *json = NULL, *net_obj = NULL;
    cJSON *dev_list = NULL, *dev_obj = NULL;
    cJSON *radio_list = NULL, *radio_obj = NULL;
    cJSON *bss_list = NULL, *bss_obj = NULL;
    cJSON *sta_list = NULL, *sta_obj = NULL;
    cJSON *disassoc_obj = NULL;
    mac_addr_str_t mac_str;
    char *json_buff = NULL;
    size_t json_len = 0;
    const bus_data_prop_t *prop = NULL;
    int timer = -1;
    int reason = -1;
    bool silent = false, silent_set = false;
    bus_error_t rc;

/* start fix 1 */
    if (name == NULL) {
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_invalid_input;
    }
/* end fix 1 */
    param = strrchr(name, '.');
    if (param == NULL) {
        em_printfout("Invalid method name");
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_invalid_input;
    }
    ++param;
    if (strcmp("Disassociate()", param) != 0) {
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
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_invalid_input;
    }
/* end fix 2 */
    name += sizeof(DATAELEMS_NETWORK);
    name = dm_ctrl->get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
/* start fix 2 */
    if (name == NULL) {
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_invalid_input;
    }
/* end fix 2 */
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
/* start fix 2 */
    if (name == NULL) {
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_invalid_input;
    }
/* end fix 2 */
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
/* start fix 2 */
    if (name == NULL) {
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_invalid_input;
    }
/* end fix 2 */
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
/* start fix 2 */
    if (name == NULL) {
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_invalid_input;
    }
/* end fix 2 */
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
        if (strcmp(prop->name, "DisassociationTimer") == 0) {
            if (!tr_181_t::tr181_get_prop_int(prop, &timer)) {
                goto invalid;
            }
        } else if (strcmp(prop->name, "ReasonCode") == 0) {
            if (!tr_181_t::tr181_get_prop_int(prop, &reason)) {
                goto invalid;
            }
        } else if (strcmp(prop->name, "Silent") == 0) {
            if (!tr_181_t::tr181_get_prop_bool(prop, &silent)) {
                goto invalid;
            }
            silent_set = true;
        } else {
invalid:
            em_printfout("Invalid parameter: %s", prop->name);
            if (output_params) {
                *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
            }
            return bus_error_invalid_input;
        }
    }
    /* Mandatory parameters: DisassociationTimer and ReasonCode. */
    if (timer < 0 || reason < 0) {
        em_printfout("Mandatory parameters missing");
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_invalid_input;
    }

    /* Prepare subdoc to be processed with command */
    subdoc = reinterpret_cast<em_subdoc_info_t *>(buff);
    memset(subdoc, 0, sizeof(em_subdoc_info_t));
    strncpy(subdoc->name, "Disassociate", sizeof(subdoc->name) - 1);

    /* Create json with root "wfa-dataelements:Disassociate" and fill
     * with necessary parameters we extract from path */
    rc = bus_error_out_of_resources;
    root = cJSON_CreateObject();
    json = cJSON_CreateObject();
    if (!root || !json) {
        em_printfout("Create object failed");
        goto cleanup;
    }
    if (!cJSON_AddItemToObject(root, "wfa-dataelements:Disassociate", json)) {
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
    dev_list = cJSON_AddArrayToObject(net_obj, "DeviceList");
    if (!dev_list) {
        em_printfout("Add DeviceList failed");
        goto cleanup;
    }
    dev_obj = cJSON_CreateObject();
    if (!dev_obj) {
        em_printfout("Create object failed");
        goto cleanup;
    }
    if (!cJSON_AddItemToArray(dev_list, dev_obj)) {
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
    radio_list = cJSON_AddArrayToObject(dev_obj, "RadioList");
    if (!radio_list) {
        em_printfout("Add RadioList failed");
        goto cleanup;
    }
    radio_obj = cJSON_CreateObject();
    if (!radio_obj) {
        em_printfout("Create object failed");
        goto cleanup;
    }
    if (!cJSON_AddItemToArray(radio_list, radio_obj)) {
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
    bss_list = cJSON_AddArrayToObject(radio_obj, "BSSList");
    if (!bss_list) {
        em_printfout("Add BSSList failed");
        goto cleanup;
    }
    bss_obj = cJSON_CreateObject();
    if (!bss_obj) {
        em_printfout("Create object failed");
        goto cleanup;
    }
    if (!cJSON_AddItemToArray(bss_list, bss_obj)) {
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
    sta_list = cJSON_AddArrayToObject(bss_obj, "STAList");
    if (!sta_list) {
        em_printfout("Add STAList failed");
        goto cleanup;
    }
    sta_obj = cJSON_CreateObject();
    if (!sta_obj) {
        em_printfout("Create object failed");
        goto cleanup;
    }
    if (!cJSON_AddItemToArray(sta_list, sta_obj)) {
        em_printfout("Add STA failed");
        cJSON_Delete(sta_obj);
        goto cleanup;
    }
    dm_easy_mesh_t::macbytes_to_string(si->id, mac_str);
    if (!cJSON_AddStringToObject(sta_obj, "MACAddress", mac_str)) {
        em_printfout("Add MACAddress failed");
        goto cleanup;
    }
    /* Currently not used, but let's add it anyway */
    if (!cJSON_AddBoolToObject(sta_obj, "Associated", si->associated)) {
        em_printfout("Add Associated failed");
        goto cleanup;
    }
    /* Add method parameters */
    disassoc_obj = cJSON_CreateObject();
    if (!disassoc_obj) {
        em_printfout("Create object failed");
        goto cleanup;
    }
    if (!cJSON_AddItemToObject(sta_obj, "Disassociate", disassoc_obj)) {
        em_printfout("Add Disassociate failed");
        cJSON_Delete(disassoc_obj);
        goto cleanup;
    }
    /* TODO: Validity check of parameters? */
    if (!cJSON_AddNumberToObject(disassoc_obj, "DisassociationTimer", timer)) {
        em_printfout("Add DisassociationTimer failed");
        goto cleanup;
    }
    if (!cJSON_AddNumberToObject(disassoc_obj, "ReasonCode", reason)) {
        em_printfout("Add ReasonCode failed");
        goto cleanup;
    }
    if (silent_set) {
        if (!cJSON_AddBoolToObject(disassoc_obj, "Silent", silent)) {
            em_printfout("Add Silent failed");
            goto cleanup;
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

    // uncomment below line to log the updated JSON before sending to DM; can be helpful for debugging.
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

    em_ctrl->io_process(em_bus_event_type_disassoc_sta, subdoc->buff, json_len);
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
    return em_ctrl_t::cmd_disassociate(method, in, out, NULL);
}
static em_ctrl_t ctrl_obj;
void set_ctrl(bool present) { ctrl_instance_ptr = present ? &ctrl_obj : NULL; }

} /* namespace cda */
