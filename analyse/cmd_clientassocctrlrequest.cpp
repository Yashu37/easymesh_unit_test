/*
 * HANDLER: cmd_clientassocctrlrequest
 *
 * Function copied (fixes 1-2 applied, start fix n / end fix n markers) from unified-wifi-mesh src/ctrl/dm_easy_mesh_ctrl.cpp
 * (develop @ 1ba9529), em_ctrl_t::cmd_clientassocctrlrequest, with get_table_instance() (same file),
 * the tr_181_t helpers it calls (tr_181_helper.cpp) and util::split_by_delim (src/utils/util.cpp).
 * Local arrays: instance[32], stalist[129], buff[sizeof(em_subdoc_info_t)+EM_IO_BUFF_SZ].
 * Scaffolding: one device 1 / radio 1 / BSS 1 (or MAC aliases 02:00:00:00:00:01 / :10:01 / :10:11),
 * io_process records what is sent. cJSON is the real library.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>
#include <string>
#include <vector>
#include "cmd_clientassocctrlrequest.h"

namespace cca {

int io_calls = 0;
char io_json[EM_IO_BUFF_SZ + 64];
unsigned int io_len = 0;
char last_status[16];
em_ctrl_t *ctrl_instance_ptr = NULL;
em_ctrl_t *em_ctrl_t::get_em_ctrl_instance() { return ctrl_instance_ptr; }

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

bus_error_t em_ctrl_t::cmd_clientassocctrlrequest(const char *method_name, const bus_data_prop_t *input_params, bus_data_prop_t **output_params, void *async_handle)
{
    (void)async_handle;
    const char *name = method_name;
    const char *param;
    char instance[MAX_INSTANCE_LEN] = { 0 };
    bool is_num;
    const bus_data_prop_t *prop = NULL;
    char stalist[TR181_STALIST_MAX_LEN + 1] = { 0 };
    bool block = false, block_set = false;
    int period = -1;
    em_subdoc_info_t *subdoc = NULL;
    unsigned char buff[sizeof(em_subdoc_info_t) + EM_IO_BUFF_SZ];
    cJSON *root = NULL, *json = NULL;
    cJSON *stalist_arr = NULL, *stalist_obj = NULL;
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
    if (strcmp("X_AIRTIES_ClientAssocControl()", param) != 0) {
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
/* start fix 1 */
    if (strlen(name) < sizeof(DATAELEMS_NETWORK)) {
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_invalid_input;
    }
/* end fix 1 */
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

    /* Most of the parameters are mandatory, parse them */
    for (prop = input_params; prop; prop = prop->next_data) {
        if (strcmp(prop->name, "StationsList") == 0) {
            if (prop->value.raw_data_len > sizeof(stalist) ||
                !tr_181_t::tr181_copy_prop_string(prop, stalist, sizeof(stalist))) {
                goto invalid;
            }
        } else if (strcmp(prop->name, "Block") == 0) {
            if (!tr_181_t::tr181_get_prop_bool(prop, &block)) {
                goto invalid;
            }
            block_set = true;
        } else if (strcmp(prop->name, "Period") == 0) {
            if (!tr_181_t::tr181_get_prop_int(prop, &period)) {
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
    /* Mandatory parameters: StationsList, Block, Period */
    if (!stalist[0] || !block_set || period < 0) {
        em_printfout("Mandatory parameters missing");
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_invalid_input;
    }
    if (static_cast<unsigned int>(period) > USHRT_MAX) {
        em_printfout("Period is out of bounds");
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_invalid_input;
    }

    /* Prepare subdoc to be processed with command */
    subdoc = reinterpret_cast<em_subdoc_info_t *>(buff);
    memset(subdoc, 0, sizeof(em_subdoc_info_t));
    strncpy(subdoc->name, "ClientAssocCtrlRequest", sizeof(subdoc->name) - 1);

    /* Create json with root "wfa-dataelements:ClientAssocCtrlRequest" and fill
     * with necessary parameters we extract from path */
    rc = bus_error_out_of_resources;
    root = cJSON_CreateObject();
    json = cJSON_CreateObject();
    if (!root || !json) {
        em_printfout("Create object failed");
        cJSON_Delete(json);
        goto cleanup;
    }
    if (!cJSON_AddItemToObject(root, "wfa-dataelements:ClientAssocCtrlRequest", json)) {
        em_printfout("Add item failed");
        cJSON_Delete(json);
        goto cleanup;
    }
    dm_easy_mesh_t::macbytes_to_string(bi->bssid.mac, mac_str);
    if (!cJSON_AddStringToObject(json, "BSSID", mac_str)) {
        em_printfout("Add BSSID failed");
        goto cleanup;
    }
    stalist_arr = cJSON_AddArrayToObject(json, "StaMacList");
    if (!stalist_arr) {
        em_printfout("Add StationsList failed");
        goto cleanup;
    }
    do {
        std::string stalist_str = stalist;
        std::vector<std::string> stas = util::split_by_delim(stalist_str, ',');
        for (unsigned int i = 0; i < stas.size(); i++) {
            stalist_obj = cJSON_CreateString(stas[i].c_str());
            if (!stalist_obj) {
                em_printfout("Create string failed");
                goto cleanup;
            }
            if (!cJSON_AddItemToArray(stalist_arr, stalist_obj)) {
                em_printfout("Add item failed");
                cJSON_Delete(stalist_obj);
                goto cleanup;
            }
        }
    } while (0);
    if (!cJSON_AddNumberToObject(json, "AssocControl", block ? 0 : 1)) {
        em_printfout("Add Block failed");
        goto cleanup;
    }
    if (!cJSON_AddNumberToObject(json, "ValidityPeriod", period)) {
        em_printfout("Add Period failed");
        goto cleanup;
    }

    /* Convert JSON back to string and store in subdoc buffer. */
    json_buff = cJSON_PrintUnformatted(root);
    if (!json_buff) {
        em_printfout("Create output buffer failed");
        rc = bus_error_out_of_resources;
        goto cleanup;
    }
    /* Ensure updated JSON fits in buffer. */
    json_len = strlen(json_buff) + 1;
    if (json_len > EM_IO_BUFF_SZ) {
        em_printfout("Buffer too big for subdoc");
        free(json_buff);
        rc = bus_error_invalid_input;
        goto cleanup;
    }
    memcpy(subdoc->buff, json_buff, json_len);

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

    em_ctrl->io_process(em_bus_event_type_client_assoc_ctrl_req, subdoc->buff, static_cast<unsigned int>(json_len));
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
    return em_ctrl_t::cmd_clientassocctrlrequest(method, in, out, NULL);
}
static em_ctrl_t ctrl_obj;
void set_ctrl(bool present) { ctrl_instance_ptr = present ? &ctrl_obj : NULL; }

} /* namespace cca */
