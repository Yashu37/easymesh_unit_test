/*
 * HANDLER: cmd_setssid
 *
 * Function copied VERBATIM from unified-wifi-mesh src/ctrl/dm_easy_mesh_ctrl.cpp
 * (develop @ 1ba9529), em_ctrl_t::cmd_setssid, together with the tr_181_t helpers it
 * calls (copied verbatim from src/ctrl/tr_181/wfa_data_model/tr_181_helper.cpp).
 * Local arrays: ssid[33], passphrase[64], band[17], addremove[17], HaulType[33],
 * AKMsAllowed[33], buff[sizeof(em_subdoc_info_t)+EM_IO_BUFF_SZ]; helpers: tok_buf[33].
 * Scaffolding: the data-model config (get_config) returns a test-chosen JSON string,
 * io_process records what is sent. cJSON is the real library.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <stdint.h>
#include "common.h"

namespace css {

/* bus types come from the ccs section of common.h (the global ones differ in other harnesses) */
using ccs::bus_error_t;
using ccs::bus_error_success; using ccs::bus_error_general; using ccs::bus_error_invalid_input; using ccs::bus_error_out_of_resources;
using ccs::bus_data_type_t; using ccs::bus_data_type_string;
using ccs::raw_data_t; using ccs::bus_data_prop_t;

#define TR181_SSID_MAX_LEN         32
#define TR181_PASSPHRASE_MAX_LEN   63
#define TR181_BAND_MAX_LEN         16
#define TR181_ADDREMOVE_MAX_LEN    16
#define TR181_HAULTYPE_MAX_LEN     32
#define TR181_AKMS_MAX_LEN         32
#define EM_IO_BUFF_SZ 4096
#undef GLOBAL_NET_ID
#define GLOBAL_NET_ID "OneWifiMesh"

typedef struct { char name[64]; char buff[0]; } __attribute__((__packed__)) em_subdoc_info_t;
typedef enum { em_bus_event_type_set_ssid = 1 } em_bus_event_type_t;

/* --- scaffolding: controller / data-model stand-ins --- */
const char *cfg_json = NULL;     /* what get_config() returns */
int io_calls = 0;
char io_json[EM_IO_BUFF_SZ + 64];
unsigned int io_len = 0;
char last_status[16];

class dm_easy_mesh_ctrl_t {
public:
    void get_config(char *net_id, em_subdoc_info_t *subdoc)
    {   (void)net_id;
        if (cfg_json) { size_t n = strlen(cfg_json); if (n > EM_IO_BUFF_SZ - 1) n = EM_IO_BUFF_SZ - 1; memcpy(subdoc->buff, cfg_json, n); subdoc->buff[n] = '\0'; }
        else subdoc->buff[0] = '\0';
    }
};
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
    static bus_error_t cmd_setssid(const char *method_name, const bus_data_prop_t *input_params, bus_data_prop_t **output_params, void *async_handle);
};
em_ctrl_t *ctrl_instance_ptr = NULL;
em_ctrl_t *em_ctrl_t::get_em_ctrl_instance() { return ctrl_instance_ptr; }

class tr_181_t {
public:
    static void tr181_trim_whitespace(char *str);
    static bool tr181_copy_prop_string(const bus_data_prop_t *prop, char *dst, size_t dst_len);
    static cJSON *create_haultype_array(const char *haul_val);
    static bool item_matches_haultype(const cJSON *item, const char *haul_val);
    static cJSON *create_akms_array(const char *akms_val);
    static const char *akms_to_auth_type(const char *akms_val);
    static const char *akms_array_to_auth_type(const cJSON *akms_arr);
    static bus_data_prop_t *tr181_set_status_output_prop(const char *status)
    {   /* stand-in for tr181_alloc_string_prop("Status", status) */
        bus_data_prop_t *p = (bus_data_prop_t *)calloc(1, sizeof(*p));
        snprintf(last_status, sizeof(last_status), "%s", status);
        p->value.data_type = bus_data_type_string;
        p->value.raw_data.bytes = strdup(status);
        return p;
    }
};

/* --- copied verbatim from src/ctrl/tr_181/wfa_data_model/tr_181_helper.cpp --- */
void tr_181_t::tr181_trim_whitespace(char *str)
{
    if (!str) {
        return;
    }
    char *start = str;
    while (isspace(static_cast<unsigned char>(*start))) {
        start++;
    }
    if (*start == '\0') {
        str[0] = '\0';
        return;
    }
    char *end = start + strlen(start) - 1;
    while (end > start && isspace(static_cast<unsigned char>(*end))) {
        end--;
    }
    size_t len = static_cast<size_t>(end - start + 1);
    if (start != str) {
        memmove(str, start, len);
    }
    str[len] = '\0';
}

cJSON *tr_181_t::create_haultype_array(const char *haul_val)
{
    if (!haul_val || *haul_val == '\0') return NULL;
    if (strchr(haul_val, ',')) {
        em_printfout("ERROR: HaulType must be a single value (no commas): '%s'", haul_val);
        return NULL;
    }
    char tok_buf[TR181_HAULTYPE_MAX_LEN + 1];
    size_t val_len = strnlen(haul_val, sizeof(tok_buf));
    if (val_len >= sizeof(tok_buf)) {
        em_printfout("ERROR: HaulType too long");
        return NULL;
    }
    memcpy(tok_buf, haul_val, val_len + 1);
    tr181_trim_whitespace(tok_buf);
    if (*tok_buf == '\0') {
        em_printfout("ERROR: HaulType empty after trimming");
        return NULL;
    }
    if (strcmp(tok_buf, "Fronthaul") != 0 && strcmp(tok_buf, "Backhaul") != 0) {
        em_printfout("ERROR: Invalid HaulType value '%s' (expected Fronthaul/Backhaul)", tok_buf);
        return NULL;
    }
    cJSON *arr = cJSON_CreateArray();
    if (!arr) {
        return NULL;
    }
    cJSON *val = cJSON_CreateString(tok_buf);
    if (!val) {
        cJSON_Delete(arr);
        return NULL;
    }
    cJSON_AddItemToArray(arr, val);
    return arr;
}

bool tr_181_t::item_matches_haultype(const cJSON *item, const char *haul_val)
{
    if (!item || !haul_val || *haul_val == '\0') return false;
    char tok_buf[TR181_HAULTYPE_MAX_LEN + 1];
    size_t val_len = strnlen(haul_val, sizeof(tok_buf));
    if (val_len >= sizeof(tok_buf)) {
        return false;
    }
    memcpy(tok_buf, haul_val, val_len + 1);
    tr181_trim_whitespace(tok_buf);
    if (*tok_buf == '\0') return false;
    const cJSON *haul_arr = cJSON_GetObjectItem(item, "HaulType");
    if (!haul_arr || !cJSON_IsArray(haul_arr)) return false;
    cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, haul_arr) {
        if (cJSON_IsString(entry) && entry->valuestring && strcmp(entry->valuestring, tok_buf) == 0) {
            return true;
        }
    }
    return false;
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

cJSON *tr_181_t::create_akms_array(const char *akms_val)
{
    if (!akms_val) return NULL;
    /* An empty list is the way TR-181 expresses that no AKM is offered. */
    if (*akms_val == '\0') return cJSON_CreateArray();
    if (strchr(akms_val, ',')) {
        em_printfout("ERROR: AKMsAllowed must be a single value (no commas): '%s'", akms_val);
        return NULL;
    }
    char tok_buf[TR181_AKMS_MAX_LEN + 1];
    size_t val_len = strnlen(akms_val, sizeof(tok_buf));
    if (val_len >= sizeof(tok_buf)) {
        em_printfout("ERROR: AKMsAllowed too long");
        return NULL;
    }
    memcpy(tok_buf, akms_val, val_len + 1);
    tr181_trim_whitespace(tok_buf);
    if (*tok_buf == '\0') {
        em_printfout("ERROR: AKMsAllowed empty after trimming");
        return NULL;
    }
    /* akm_t enum values that map to a WSC M2 auth type on this stack. */
    if (strcmp(tok_buf, "psk") != 0 && strcmp(tok_buf, "sae") != 0 &&
        strcmp(tok_buf, "psk+sae") != 0) {
        em_printfout("ERROR: Invalid/unsupported AKMsAllowed value '%s' (expected psk/sae/psk+sae)", tok_buf);
        return NULL;
    }
    cJSON *arr = cJSON_CreateArray();
    if (!arr) {
        return NULL;
    }
    cJSON *val = cJSON_CreateString(tok_buf);
    if (!val) {
        cJSON_Delete(arr);
        return NULL;
    }
    cJSON_AddItemToArray(arr, val);
    return arr;
}

const char *tr_181_t::akms_to_auth_type(const char *akms_val)
{
    if (akms_val == NULL) {
        return NULL;
    }
    if (strcmp(akms_val, "psk") == 0) return "WPA2 Personal";
    if (strcmp(akms_val, "sae") == 0) return "WPA3 Personal";
    if (strcmp(akms_val, "psk+sae") == 0) return "WPA3 Transition";
    return NULL;
}

const char *tr_181_t::akms_array_to_auth_type(const cJSON *akms_arr)
{
    if (akms_arr == NULL) {
        return NULL;
    }
    if (cJSON_GetArraySize(const_cast<cJSON *>(akms_arr)) == 0) {
        return "Open";
    }
    return akms_to_auth_type(cJSON_GetStringValue(cJSON_GetArrayItem(const_cast<cJSON *>(akms_arr), 0)));
}

/* --- copied verbatim from src/ctrl/dm_easy_mesh_ctrl.cpp --- */
bus_error_t em_ctrl_t::cmd_setssid(const char *method_name, const bus_data_prop_t *input_params, bus_data_prop_t **output_params, void *async_handle)
{
    em_subdoc_info_t *subdoc = NULL;
    unsigned char buff[sizeof(em_subdoc_info_t) + EM_IO_BUFF_SZ];
    cJSON *json = NULL, *root = NULL, *new_json = NULL, *ssid_list = NULL, *target = NULL, *item = NULL, *ssid_item = NULL, *child = NULL, *next = NULL, *band_arr = NULL;
    char *updated_json = NULL;
    const bus_data_prop_t *prop = NULL;
    char ssid[TR181_SSID_MAX_LEN + 1] = {0};
    char passphrase[TR181_PASSPHRASE_MAX_LEN + 1] = {0};
    char band[TR181_BAND_MAX_LEN + 1] = {0};
    char addremove[TR181_ADDREMOVE_MAX_LEN + 1] = {0};
    char HaulType[TR181_HAULTYPE_MAX_LEN + 1] = {0};
    char AKMsAllowed[TR181_AKMS_MAX_LEN + 1] = {0};
    bool akms_given = false;
    size_t json_len = 0;

    (void)method_name;
    (void)async_handle;

    if (!input_params) {
        if (output_params) *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        return bus_error_invalid_input;
    }

    // Parse input parameters
    for (prop = input_params; prop; prop = prop->next_data) {
        if (strcmp(prop->name, "SSID") == 0) {
            tr_181_t::tr181_copy_prop_string(prop, ssid, sizeof(ssid));
        } else if (strcmp(prop->name, "AddRemoveChange") == 0) {
            tr_181_t::tr181_copy_prop_string(prop, addremove, sizeof(addremove));
        } else if (strcmp(prop->name, "PassPhrase") == 0) {
            tr_181_t::tr181_copy_prop_string(prop, passphrase, sizeof(passphrase));
        } else if (strcmp(prop->name, "Band") == 0) {
            tr_181_t::tr181_copy_prop_string(prop, band, sizeof(band));
        } else if (strcmp(prop->name, "HaulType") == 0) {
            tr_181_t::tr181_copy_prop_string(prop, HaulType, sizeof(HaulType));
        } else if (strcmp(prop->name, "AKMsAllowed") == 0) {
            /* An empty string is Open, a failed copy is not: both leave the buffer empty. */
            if (tr_181_t::tr181_copy_prop_string(prop, AKMsAllowed, sizeof(AKMsAllowed)) == false) {
                if (output_params) *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
                return bus_error_invalid_input;
            }
            akms_given = true;
            /* Full buffer = truncated input, longer than any valid akm_t value. */
            if (strnlen(AKMsAllowed, sizeof(AKMsAllowed)) >= TR181_AKMS_MAX_LEN) {
                if (output_params) *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
                return bus_error_invalid_input;
            }
        }
    }

    //Mandatory parameters: SSID and AddRemoveChange.
    if (!ssid[0] || !addremove[0]) {
        if (output_params) *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        return bus_error_invalid_input;
    }

    // Initialize subdoc with NetworkSSIDList template.
    subdoc = reinterpret_cast<em_subdoc_info_t *>(buff);
    memset(subdoc, 0, sizeof(em_subdoc_info_t));
    strncpy(subdoc->name, "NetworkSSIDList", sizeof(subdoc->name) - 1);

    // get current config for NetworkSSIDList and parse as JSON.
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();
    if (!em_ctrl) {
        if (output_params) *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        return bus_error_invalid_input;
    }
    em_ctrl->get_dm_ctrl()->get_config(const_cast<char *>(GLOBAL_NET_ID), subdoc);
    json = cJSON_Parse(subdoc->buff);
    if (!json) {
        if (output_params) *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        return bus_error_invalid_input;
    }

    // Create new JSON with root "wfa-dataelements:SetSSID" and move existing items under it.
    root = cJSON_CreateObject();
    new_json = cJSON_CreateObject();
    if (!root || !new_json) {
        cJSON_Delete(root);
        cJSON_Delete(new_json);
        cJSON_Delete(json);
        if (output_params) *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        return bus_error_out_of_resources;
    }
    if (!cJSON_AddStringToObject(new_json, "ID", GLOBAL_NET_ID)) {
        cJSON_Delete(root);
        cJSON_Delete(new_json);
        cJSON_Delete(json);
        if (output_params) *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        return bus_error_out_of_resources;
    }

    // Move all items from original JSON to new JSON under "wfa-dataelements:SetSSID".
    child = json->child;
    while (child) {
        next = child->next;
        cJSON_DetachItemViaPointer(json, child);
        cJSON_AddItemToObject(new_json, child->string, child);
        child = next;
    }
    cJSON_Delete(json);

    // Add new JSON as child of root and update subdoc buffer.
    json = new_json;
    new_json = NULL;
    cJSON_AddItemToObject(root, "wfa-dataelements:SetSSID", json);

    ssid_list = cJSON_GetObjectItem(json, "NetworkSSIDList");
    if (!ssid_list || !cJSON_IsArray(ssid_list)) {
        cJSON_Delete(root);
        if (output_params) *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        return bus_error_invalid_input;
    }

    // Validate AddRemoveChange value and determine operation type.
    bool is_add = (strcmp(addremove, "Add") == 0);
    bool is_remove = (strcmp(addremove, "Remove") == 0);
    bool is_change = (strcmp(addremove, "Change") == 0);
    if (!is_add && !is_remove && !is_change) {
        cJSON_Delete(root);
        if (output_params) *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        return bus_error_invalid_input;
    }

    // If HaulType provided, create array for comparison/assignment (only for Add or Change).
    cJSON *haul_arr = NULL;
    if ((is_add || is_change) && HaulType[0]) {
    haul_arr = tr_181_t::create_haultype_array(HaulType);
        if (!haul_arr) {
            cJSON_Delete(root);
            if (output_params) *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
            return bus_error_invalid_input;
        }
    }

    // Search for existing item to change/remove (match by HaulType if provided, otherwise by SSID).
    int target_index = -1, ssid_idx = 0;
    bool match_by_haul = (is_change && HaulType[0]);
    cJSON_ArrayForEach(item, ssid_list) {
        if (match_by_haul) {
            if (tr_181_t::item_matches_haultype(item, HaulType)) {
                target = item;
                target_index = ssid_idx;
                break;
            }
        } else {
            ssid_item = cJSON_GetObjectItem(item, "SSID");
            if (cJSON_IsString(ssid_item) && ssid_item->valuestring && strcmp(ssid_item->valuestring, ssid) == 0) {
                target = item;
                target_index = ssid_idx;
                break;
            }
        }
        ssid_idx++;
    }

    // Perform requested operation on target item.
    // For Add, create new item. For Change/Remove, modify/delete existing item.
    if (target) {
        if (is_remove) {
            if (target_index >= 0) cJSON_DeleteItemFromArray(ssid_list, target_index);
        } else {
            if (ssid[0]) {
                cJSON *ssid_item_new = cJSON_CreateString(ssid);
                if (!ssid_item_new) {
                    if (haul_arr) cJSON_Delete(haul_arr);
                    cJSON_Delete(root);
                    if (output_params) *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
                    return bus_error_out_of_resources;
                }
                cJSON_ReplaceItemInObject(target, "SSID", ssid_item_new);
            }
            if (passphrase[0]) {
                cJSON *passphrase_item = cJSON_CreateString(passphrase);
                if (!passphrase_item) {
                    if (haul_arr) cJSON_Delete(haul_arr);
                    cJSON_Delete(root);
                    if (output_params) *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
                    return bus_error_out_of_resources;
                }
                cJSON_ReplaceItemInObject(target, "PassPhrase", passphrase_item);
            }
            if (band[0]) {
                band_arr = cJSON_CreateArray();
                if (!band_arr) {
                    if (haul_arr) cJSON_Delete(haul_arr);
                    cJSON_Delete(root);
                    if (output_params) *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
                    return bus_error_out_of_resources;
                }
                cJSON *band_item = cJSON_CreateString(band);
                if (!band_item) {
                    cJSON_Delete(band_arr);
                    if (haul_arr) cJSON_Delete(haul_arr);
                    cJSON_Delete(root);
                    if (output_params) *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
                    return bus_error_out_of_resources;
                }
                cJSON_AddItemToArray(band_arr, band_item);
                cJSON_ReplaceItemInObject(target, "Band", band_arr);
            }
            if (haul_arr) {
                cJSON_ReplaceItemInObject(target, "HaulType", haul_arr);
                haul_arr = NULL;
            }
            if (akms_given) {
                /* BBF TR-181 SetSSID() input AKMsAllowed (since 2.17): update the
                 * entry's AKMsAllowed and derive the internal AuthType used to
                 * build the WSC M2 auth type. An empty value is an empty list,
                 * which selects an open BSS. */
                cJSON *akms_arr = tr_181_t::create_akms_array(AKMsAllowed);
                if (!akms_arr) {
                    cJSON_Delete(root);
                    if (output_params) *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
                    return bus_error_invalid_input;
                }
                const char *auth_str = tr_181_t::akms_array_to_auth_type(akms_arr);
                cJSON *auth_item = (auth_str != NULL) ? cJSON_CreateString(auth_str) : NULL;
                if (!auth_item) {
                    cJSON_Delete(akms_arr);
                    cJSON_Delete(root);
                    if (output_params) *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
                    return bus_error_out_of_resources;
                }
                cJSON_ReplaceItemInObject(target, "AKMsAllowed", akms_arr);
                cJSON_ReplaceItemInObject(target, "AuthType", auth_item);
            }
        }
    } else if (is_add) {
        target = cJSON_CreateObject();
        if (!target) {
            if (haul_arr) cJSON_Delete(haul_arr);
            cJSON_Delete(root);
            if (output_params) *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
            return bus_error_out_of_resources;
        }
        cJSON_AddItemToArray(ssid_list, target);
        if (ssid[0] && !cJSON_AddStringToObject(target, "SSID", ssid)) {
            if (haul_arr) cJSON_Delete(haul_arr);
            cJSON_Delete(root);
            if (output_params) *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
            return bus_error_out_of_resources;
        }
        if (passphrase[0] && !cJSON_AddStringToObject(target, "PassPhrase", passphrase)) {
            if (haul_arr) cJSON_Delete(haul_arr);
            cJSON_Delete(root);
            if (output_params) *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
            return bus_error_out_of_resources;
        }
        if (band[0]) {
            band_arr = cJSON_CreateArray();
            if (!band_arr) {
                if (haul_arr) cJSON_Delete(haul_arr);
                cJSON_Delete(root);
                if (output_params) *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
                return bus_error_out_of_resources;
            }
            cJSON *band_item = cJSON_CreateString(band);
            if (!band_item) {
                cJSON_Delete(band_arr);
                if (haul_arr) cJSON_Delete(haul_arr);
                cJSON_Delete(root);
                if (output_params) *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
                return bus_error_out_of_resources;
            }
            cJSON_AddItemToArray(band_arr, band_item);
            cJSON_AddItemToObject(target, "Band", band_arr);
        }
        if (haul_arr) {
            cJSON_AddItemToObject(target, "HaulType", haul_arr);
            haul_arr = NULL;
        }
        if (akms_given) {
            cJSON *akms_arr = tr_181_t::create_akms_array(AKMsAllowed);
            if (!akms_arr) {
                cJSON_Delete(root);
                if (output_params) *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
                return bus_error_invalid_input;
            }
            const char *auth_str = tr_181_t::akms_array_to_auth_type(akms_arr);
            cJSON *auth_item = (auth_str != NULL) ? cJSON_CreateString(auth_str) : NULL;
            if (!auth_item) {
                cJSON_Delete(akms_arr);
                cJSON_Delete(root);
                if (output_params) *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
                return bus_error_out_of_resources;
            }
            cJSON_AddItemToObject(target, "AKMsAllowed", akms_arr);
            cJSON_AddItemToObject(target, "AuthType", auth_item);
        }
    } else {
        if (haul_arr) cJSON_Delete(haul_arr);
        cJSON_Delete(root);
        if (output_params) *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        return bus_error_invalid_input;
    }

    // Convert updated JSON back to string and store in subdoc buffer.
    updated_json = cJSON_PrintUnformatted(root);
    if (!updated_json) {
        cJSON_Delete(root);
        if (output_params) *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        return bus_error_out_of_resources;
    }

    // Ensure updated JSON fits in buffer.
    json_len = strlen(updated_json);
    if (json_len >= EM_IO_BUFF_SZ) {
        free(updated_json);
        cJSON_Delete(root);
        if (output_params) *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        return bus_error_invalid_input;
    }

    memcpy(subdoc->buff, updated_json, json_len);
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

    em_ctrl->io_process(em_bus_event_type_set_ssid, subdoc->buff, json_len);
    free(updated_json);
    cJSON_Delete(root);

    if (output_params) *output_params = tr_181_t::tr181_set_status_output_prop("Success");
    return bus_error_success;
}

bus_error_t invoke(const bus_data_prop_t *in, bus_data_prop_t **out)
{
    return em_ctrl_t::cmd_setssid("Device.WiFi.DataElements.Network.SetSSID()", in, out, NULL);
}

static em_ctrl_t ctrl_obj;
void set_ctrl(bool present) { ctrl_instance_ptr = present ? &ctrl_obj : NULL; }

} /* namespace css */
